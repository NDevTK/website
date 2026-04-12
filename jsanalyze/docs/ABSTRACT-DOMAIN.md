# Abstract domain

This document defines the abstract domain jsanalyze operates over:
the lattice of abstract values, the abstract state at each program
point, the transfer functions per IR instruction, and the worklist
fixpoint algorithm.

## Abstract values

```
Value ::=
  ⊥                                -- unreachable / no value
  Concrete(prim | ObjRef)          -- single known primitive or heap ref
  OneOf(Set<Concrete>)             -- finite disjunction of concretes
  Interval(lo, hi)                 -- numeric range [lo, hi]
  StrPattern({prefix?, suffix?,
              contains?,
              length?})            -- structural string refinement
  Type(TypeName)                    -- runtime type only (no value content)
  Closure(FuncId, env)             -- function closure + captured env
  Opaque(assumptionIds[])           -- unknown; records why
  ⊤                                -- any value
```

### Lattice order

Values form a lattice with `⊥ ⊑ every value ⊑ ⊤`. Between the
extremes:

- `Concrete(v)` is below `OneOf({v, w, ...})` containing it
- `Concrete(n)` where `n` is a number is below `Interval(lo, hi)` if `lo ≤ n ≤ hi`
- `Concrete(s)` where `s` is a string is below `StrPattern` if the pattern matches `s`
- Any of the refinements is below `Type(t)` for its corresponding type
- `Type(t)` is below `⊤`

The join `⊔_Value` computes the least upper bound:
- `Concrete(a) ⊔ Concrete(a) = Concrete(a)`
- `Concrete(a) ⊔ Concrete(b) = OneOf({a, b})` when `a ≠ b`
- `OneOf(S) ⊔ OneOf(T) = OneOf(S ∪ T)`
- `Interval(a, b) ⊔ Interval(c, d) = Interval(min(a,c), max(b,d))`
- Any mismatch (string vs number, concrete vs interval, …) is joined at `Type` if a common type exists, else `⊤`.

**No widening.** The may-be lattice has no artificial size cap.
Termination is guaranteed by the IR structure (finite blocks,
finite registers) plus a monotone convergence check on the work-
list.

## Heap model

```
Heap ::= Map<ObjId, Object>
Object ::= { kind, fields: Map<FieldKey, Value>, typeName: Type, origin: Location }
FieldKey ::= string | number | '__proto__' | '__symbol_iterator' | ...
```

Every allocation (`Alloc`, `Func`, `New`) produces a fresh `ObjId`
at a specific source location. The ObjId is stable — distinct
allocations have distinct ids even if they allocate the same
shape. This gives full **field sensitivity** (distinct objects
track distinct field values) and **flow sensitivity** (field
values may change over time within the same object).

Heap writes are point-wise:
```
writeField(heap, objId, key, value):
  heap'[objId] = heap[objId] with fields[key] := value
```

Heap reads consult the current abstract object:
```
readField(heap, objId, key):
  return heap[objId].fields[key] or ⊤ if missing
```

### Aliasing

Values that hold the same `ObjId` are aliases. Writing through
any alias updates the shared heap cell. Two different allocations
at different source locations produce different `ObjId`s even if
they syntactically construct the same shape — they are not
aliased.

### Escape tracking

When an ObjId flows into an opaque call, external module, or
dynamic dispatch target, it is marked as **escaped**. All
subsequent reads from an escaped object's fields yield `⊤` with
a `heap-escape` assumption attached. Writes are still tracked but
the analyser knows they may be invalidated by the opaque world.

## Abstract state

```
State ::= {
  regs: Map<Register, Value>,        -- SSA register values
  heap: Heap,                         -- current heap snapshot
  path: Formula,                      -- accumulated path condition (SMT-LIB AST)
  effects: List<Effect>,              -- writes made on this path
  assumptions: Set<AssumptionId>,     -- assumptions accumulated on this path
  callStack: List<(FuncId, ArgsFingerprint)>,  -- for recursion detection
}
```

The state lattice joins component-wise:
- `regs`: point-wise `⊔_Value` per register, missing registers default to `⊥`
- `heap`: point-wise per ObjId, missing objects default to `⊥`
- `path`: disjunction (`∨`) — both paths may be possible at a merge
- `effects`: set union
- `assumptions`: set union
- `callStack`: must match exactly (different call contexts = different states)

## Transfer functions

Each IR instruction has a transfer function `⟦instr⟧ : State → State`.

### Const

```
⟦Const(dest, lit)⟧ state = state[regs[dest] := Concrete(lit)]
```

### BinOp

```
⟦BinOp(dest, op, left, right)⟧ state =
  let l = state.regs[left]
      r = state.regs[right]
      v = applyBinOp(op, l, r)
  in state[regs[dest] := v]
```

`applyBinOp` cascades:
1. If both operands are `Concrete` with matching types, compute the concrete result.
2. If one is `Interval`, compute an interval result (e.g. `Interval(a,b) + Concrete(c) = Interval(a+c, b+c)`).
3. If both are `StrPattern` and the op is `+`, concatenate the patterns.
4. Otherwise, the result is `Type(inferResultType(op, l, r))` or `⊤`.

### GetProp / SetProp

```
⟦GetProp(dest, obj, prop)⟧ state =
  let v = state.regs[obj]
  in case v of
       Concrete(objRef) → state[regs[dest] := readField(state.heap, objRef, prop)]
       OneOf({o1,...}) → state[regs[dest] := ⊔ readField(heap, oi, prop)]
       Opaque(ids)    → state[regs[dest] := Opaque(ids)]
       _              → state[regs[dest] := ⊤]

⟦SetProp(obj, prop, val)⟧ state =
  let v = state.regs[obj]
      w = state.regs[val]
  in case v of
       Concrete(objRef) → state[heap := writeField(state.heap, objRef, prop, w)]
       OneOf({o1,...}) → weak update: heap := ⊔ writeField(heap, oi, prop, w)
       Opaque(ids)    → state[assumptions := assumptions ∪ ids]  // write lost
       _              → state[...assumption: heap-escape]
```

### Phi

```
⟦Phi(dest, incoming)⟧ state =
  -- incoming is processed at block-entry time; the Phi collects
  -- the source values from each predecessor block's exit state
  -- and joins them.
  let vs = [predExitState(b).regs[r] | (b, r) ∈ incoming,
                                       b is reachable]
  in state[regs[dest] := ⊔ vs]
```

### Branch

```
⟦Branch(cond, T, F)⟧ state =
  let c = state.regs[cond]
      reach_T = isReachable(c, T) under state.path
      reach_F = isReachable(¬c, F) under state.path
  in if reach_T: queue T with state[path := path ∧ c]
     if reach_F: queue F with state[path := path ∧ ¬c]
```

`isReachable` is the cascaded reachability check (see next
section).

### Call

```
⟦Call(dest, callee, args, thisArg)⟧ state =
  let c = state.regs[callee]
  in case c of
       Closure(fnId, env) → instantiate(fnId, env, args, thisArg, state)
       Concrete(typeRef)  → lookup TypeDB method descriptor
       OneOf({c1, c2, ...}) → ⊔ over each callee target
       Opaque(ids)  → state[regs[dest] := Opaque(ids ∪ {opaque-call})]
       _            → state[regs[dest] := ⊤ with opaque-call assumption]

instantiate(fnId, env, args, thisArg, state) =
  -- Check the call stack for exact (fnId, argFingerprint) duplicate
  -- (true recursion). If present, return Opaque(unsolvable-math).
  -- Otherwise push the call frame and run the worklist on the
  -- callee's CFG starting from a state with params bound to args.
```

### Function summary caching

Once a function has been walked with a specific abstract input
state, its `(inputState, outputState, effects)` triple is stored
as a **summary**. Subsequent calls with the same abstract input
state replay the summary instead of re-walking.

The summary key is the **minimal relevant slice** of the input
state — only the registers and heap cells the body actually
reads. This is computed as a side effect of the first walk.

Summaries are never widened; a miss on the summary key means a
fresh walk, which eventually adds a new summary entry. The
summary table size is bounded by the product of distinct input
states the body is called with across the program.

## Reachability cascade

At each branch, the analyser determines reachability of the true
and false successors via a cascade of increasingly expensive
checks:

### Layer 1: structural

- If the block has no predecessors and is not the entry: unreachable.
- If the block follows an unconditional `Return`, `Throw`, or
  `Unreachable` terminator: unreachable.

Complexity: O(1). No calls.

### Layer 2: constant folding

- If `cond` is `Concrete(bool)` or a constant arithmetic result,
  the branch is decided by the constant.
- If `cond` is `Concrete(n)` for a non-bool, apply JS truthiness
  rules to fold.

Complexity: O(1). No calls.

### Layer 3: value-set refutation

- If `cond` is `OneOf({…})`, intersect with the truthy set and
  the falsy set. If one side is empty, that branch is unreachable.
- If `cond` is `Interval(lo, hi)`, intersect with `>0` and `≤0`
  (for numbers) or analogous checks for other types.
- If `cond` is an equality `left == right` and both sides are
  `OneOf`, compute the set intersection; empty means unreachable.

Complexity: O(|value set|). No solver calls.

### Layer 4: path-sensitive propagation

- Refine the enclosing state's register values using the branch
  condition. `if (x === "admin")` refines `x` to `Concrete("admin")`
  in the true branch, and `x ∈ knownSet - {"admin"}` in the false.
- If any register becomes `⊥` after refinement, the branch is
  unreachable.

Complexity: O(refined registers). No solver calls.

### Layer 5: SMT

- Encode the accumulated path condition + the branch condition
  as an SMT-LIB formula and ask Z3 whether the conjunction is
  satisfiable.
- Unsat → unreachable.
- Sat → reachable.
- Unknown → record `unsolvable-math` assumption and treat as
  reachable.

Complexity: one Z3 call per unresolved branch. Heavily cached.

### Layer 6: sound over-approximation

If Layer 5 returned unknown, the branch is treated as reachable
with the assumption attached. Findings on this branch are still
sound; they may over-report.

## Worklist algorithm

```
function analyse(module, initialState):
  blockStates = Map()
  worklist = new Queue()
  worklist.push((module.top.cfg.entry, initialState))

  while worklist not empty:
    (block, inState) = worklist.dequeue()
    oldState = blockStates[block] or ⊥
    joinedIn = oldState ⊔ inState
    if joinedIn == oldState: continue     -- no new information
    blockStates[block] = joinedIn
    outState = transfer(block, joinedIn)
    for (succ, succState) in reachableSuccessors(block, outState):
      worklist.push((succ, succState))

  return blockStates
```

Termination: the state lattice has finite ascending chains
because each block's register set is fixed (finite SSA names)
and each register's value is drawn from a lattice whose height
is bounded by the number of distinct concrete values actually
observed in the program. The worklist only processes a block
when its inState joined with existing is strictly larger —
otherwise it skips. Strict growth on a finite lattice terminates.

Iteration order: block-label priority, with back edges processed
last to give forward propagation a chance before loop re-visits.
The exact order does not affect the final result (monotone
lattice) but affects convergence speed.

## Context sensitivity

Each function call frame stores `(FunctionId, ArgsFingerprint)`
on the call stack component of the state. The summary cache is
keyed by this fingerprint, giving **k-CFA-style context sensitivity
with k equal to the number of distinct concrete argument
fingerprints the caller produces**.

Recursive calls with the **same** fingerprint hit the stack and
return `Opaque(unsolvable-math)`. Recursive calls with
**different** fingerprints (progress toward a base case) proceed
normally, bounded by the finite set of fingerprints reachable
from the entry.

## Soundness theorem (informal)

**Claim.** For every concrete execution trace τ of the analysed
program that propagates a value with label ℓ from a TypeDB-
declared source to a TypeDB-declared sink, either:

1. The analyser emits a finding at the sink location with ℓ in
   the source set, OR
2. The analyser emits at least one `Assumption` with `severity:
   soundness` on the path from source to sink.

In other words: if you audit all `soundness` assumptions in a
trace, you have a complete record of where the analyser's
guarantee breaks down. Absence of `soundness` assumptions implies
absence of missed flows.

This theorem is the **design target** of the library. The current
implementation is being built toward it; unimplemented features
raise `soundness`-class assumptions so downstream consumers
always know where the floor is.

## References

- Cousot & Cousot, *Abstract Interpretation: A Unified Lattice Model for Static Analysis of Programs*. POPL 1977.
- Kam & Ullman, *Monotone Data Flow Analysis Frameworks*. Acta Informatica 1977.
- Sharir & Pnueli, *Two Approaches to Interprocedural Data Flow Analysis*. 1981.
- Reps, Horwitz & Sagiv, *Precise Interprocedural Dataflow Analysis via Graph Reachability*. POPL 1995.
- Jensen, Møller, Thiemann, *Type Analysis for JavaScript* (TAJS). SAS 2009.

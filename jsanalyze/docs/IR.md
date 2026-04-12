# IR: Intermediate Representation

jsanalyze lowers the acorn AST into a typed SSA intermediate
representation before analysis. The IR is the only shape the
analysis engine sees — transfer functions dispatch on IR
instruction kinds, the worklist operates on IR basic blocks, and
the query layer resolves locations back to AST nodes via the
IR's source-location mapping.

This document is the formal definition of the IR. Every AST
construct has exactly one IR lowering; every IR instruction has
exactly one transfer function.

## Form

Static single assignment (SSA). Every variable is assigned
exactly once in the IR; multiple source-level assignments become
distinct IR temporaries, with φ (phi) instructions at control-
flow merges.

Values are referenced by **virtual register** — an opaque small
integer unique within a function. There are no named variables in
the IR; name resolution is done at AST→IR lowering time by
mapping source identifiers to the register of their most recent
definition.

## Module structure

```
Module = {
  name: string,
  sourceMap: Map<InstrId, Location>,  // InstrId → original source position
  functions: Function[],
  top: Function,                       // the top-level program
  typeDB: TypeDB,                      // active TypeDB for this module
}

Function = {
  id: FunctionId,
  name: string | null,
  params: Register[],                   // registers bound to caller args
  thisReg: Register | null,             // `this` register, if applicable
  cfg: ControlFlowGraph,
  captures: Register[],                 // registers from enclosing scopes
  returns: Register[],                  // registers that flow into return
  isGenerator: bool,
  isAsync: bool,
}

ControlFlowGraph = {
  entry: BlockId,
  exit:  BlockId,
  blocks: Map<BlockId, BasicBlock>,
}

BasicBlock = {
  id: BlockId,
  instructions: Instruction[],
  terminator: Terminator,
  preds: BlockId[],
  succs: BlockId[],
  // Every block has one terminator and zero or more ordinary
  // instructions. A block contains no branches except via its
  // terminator — this is what makes it a "basic" block.
}
```

## Instruction set

All instructions have the form `Instr(kind, dest?, ...operands)`.
`dest` is the register written (if any). `kind` dispatches the
transfer function.

### Value-producing instructions

```
Const(dest, literal)
  literal ∈ { null, undefined, boolean, number, bigint, string, regex }
  Writes `dest` with a concrete literal value.

Alloc(dest, kind, fields?)
  kind ∈ { object, array, map, set, weakmap, weakset, promise, date, regex }
  Allocates a fresh heap object. `dest` receives an ObjectRef.
  For object: `fields` is a list of (key, register) pairs.
  For array: `fields` is a list of registers (elements).

Func(dest, functionId, captures)
  Creates a closure over `functionId` capturing the listed
  registers. `dest` receives a Closure value.

Phi(dest, [(pred_block, source_reg)])
  Control-flow merge. `dest` equals the value from `source_reg`
  in whichever predecessor block's edge the control flow came
  through. Every incoming block edge must be represented.

BinOp(dest, op, left, right)
  op ∈ { +, -, *, /, %, **, ==, !=, ===, !==, <, <=, >, >=,
         &&, ||, ??, &, |, ^, <<, >>, >>>, in, instanceof }
  Operates on two source registers.

UnOp(dest, op, operand)
  op ∈ { -, +, !, ~, typeof, void, delete }

GetProp(dest, object, propName)
  propName is a constant string (object.propName).
  Writes `dest` with the property value, looked up by the heap model.

GetIndex(dest, object, key)
  key is a register (object[key]).

GetGlobal(dest, name)
  name is a global identifier. Resolved via the TypeDB roots.

GetThis(dest)
  Reads the current function's `this`.

GetArguments(dest)
  Reads the `arguments` object (legacy).

Call(dest, callee, args, thisArg?)
  Calls `callee` with `args` and optional `thisArg`. Writes `dest`
  with the returned value.

New(dest, ctor, args)
  Constructor invocation.

Cast(dest, source, typeName)
  Type refinement (e.g. from a `typeof` or `instanceof` guard
  inside a branch). Propagates the source value but narrows the
  type in the abstract domain.

Opaque(dest, reason, details, affects)
  Creates an Opaque value referencing an assumption. Used when
  the AST→IR lowering can't represent a construct exactly.
```

### Side-effecting instructions

```
SetProp(object, propName, value)
  object.propName = value

SetIndex(object, key, value)
  object[key] = value

SetGlobal(name, value)
  Writes a global binding.

DeleteProp(object, propName)
DeleteIndex(object, key)
  Deletes a property.

Throw(value)
  Unwinds to the nearest enclosing catch or module exit.
```

### Terminators

Every basic block ends in exactly one terminator.

```
Jump(target)
  Unconditional branch.

Branch(cond, trueTarget, falseTarget)
  Conditional branch based on the truthiness of `cond`.

Return(value?)
  Returns from the enclosing function.

Throw(value)
  Throws (same as the side-effecting instruction but used as a
  terminator when it's the last statement of a block).

Switch(disc, cases, default)
  cases = [(value, target)]
  Multi-way branch on `disc` against each case's constant.
  Used for `switch` statements with constant cases.

Unreachable()
  Marker for blocks the analyser proves unreachable. Kept in
  the CFG for source-location reporting; never executed by the
  worklist.
```

## AST → IR lowering

The lowering pass (`ir.js`) walks the acorn AST top-down and emits
instructions + blocks. It is purely syntactic — no abstract values
or type reasoning happens here. The lowering preserves every
location via `sourceMap` so downstream analysis can report
findings at the original source positions.

Key lowering patterns:

### Variable declarations

```js
var x = 1;
```
lowers to:
```
  %t1 = Const(1)
  %x0 = %t1                // var binding gets SSA register %x0
```

### Reassignment

```js
var x = 1;
x = 2;
```
lowers to:
```
  %t1 = Const(1)
  %x0 = %t1
  %t2 = Const(2)
  %x1 = %t2                // new SSA register for the reassignment
```

### if/else with merge

```js
var x;
if (cond) { x = 1; } else { x = 2; }
use(x);
```
lowers to:
```
  B0 (entry):
    %cond = ...
    Branch(%cond, B1, B2)
  B1 (then):
    %t1 = Const(1)
    %x0 = %t1
    Jump(B3)
  B2 (else):
    %t2 = Const(2)
    %x1 = %t2
    Jump(B3)
  B3 (merge):
    %x2 = Phi([(B1, %x0), (B2, %x1)])
    Call(_, %use, [%x2])
```

### while loop

```js
while (cond) { body }
```
lowers to:
```
  B0: Jump(B1)
  B1 (header):
    %cond = ...
    Branch(%cond, B2, B3)
  B2 (body):
    body...
    Jump(B1)
  B3 (after):
    ...
```

Variables modified inside the loop get φ instructions at the
header block, with edges from the preheader (B0) and the latch
(B2).

### Function declarations

Each function definition creates a new `Function` in the module.
Nested functions have their parent's registers listed in
`captures` if they're referenced from the inner function's body.

### Closures

Closure capture is explicit: the `Func` instruction at the
creation site lists exactly which outer registers the closure
references. When the closure is called later, the callee's
`captures` are bound to those same values at call time.

### try / catch / finally

```
  B0: Jump(B1)
  B1 (try body):
    ...
    Jump(B2)        // or Throw(...) → B3
  B2 (after try):
    finally body
    Jump(B4)
  B3 (catch):
    %err = ... (exception)
    catch body
    Jump(B2)
  B4 (after finally):
    ...
```

Every instruction inside a try body has a phantom edge to the
catch block (if any), so transfer functions can propagate
exception state. The exceptional edges are kept out of the main
CFG flow to avoid quadratic blowup.

### async / await

`async function` lowers to a normal function whose CFG is split at
every `await`. Each split introduces a suspend point — the
current block ends with a `Jump` to a resumption block, and the
analyser's callback fixpoint re-walks the resumption when the
awaited value is resolved.

## Source location mapping

Every IR instruction is associated with a source range via
`module.sourceMap`. The query layer uses this to present findings
at their original locations. The IR itself never stores strings
or line numbers inline — the mapping is external so the IR stays
small and cache-friendly.

## Worked example

Source:
```js
var x = 1;
var y;
if (x > 0) y = 'yes';
else y = 'no';
var z = y + '!';
```

IR after lowering:
```
B0 (entry):
  %t1 = Const(1)
  %x = %t1
  %t2 = Const(0)
  %cond = BinOp(>, %x, %t2)
  Branch(%cond, B1, B2)
B1 (then):
  %t3 = Const("yes")
  %y0 = %t3
  Jump(B3)
B2 (else):
  %t4 = Const("no")
  %y1 = %t4
  Jump(B3)
B3 (merge):
  %y = Phi([(B1, %y0), (B2, %y1)])
  %t5 = Const("!")
  %z = BinOp(+, %y, %t5)
  Return(undefined)
```

Abstract interpretation over this IR:
- %x is `Concrete(1)` after B0
- %cond is `Concrete(true)` (1 > 0 folds at layer 2)
- B1 is reachable, B2 is unreachable
- %y at B3 resolves to `Concrete("yes")` (the phi's other input is from a dead block)
- %z resolves to `Concrete("yes!")`

No SMT calls were needed; layer 2 (value-set folding) decided
everything.

## Invariants

1. Every block has exactly one terminator, at the end.
2. Every block has at least one predecessor, except the entry.
3. Every register is written exactly once (SSA).
4. Every use of a register dominates its definition.
5. Every φ has one incoming edge per predecessor block.
6. The CFG is connected from the entry.
7. The source map covers every instruction.

These invariants are checked at IR build time and on every
analysis pass via `validateModule(module)`.

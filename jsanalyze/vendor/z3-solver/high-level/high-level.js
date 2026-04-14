"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApi = createApi;
// TODO(ritave): Add typing for Context Options
//               https://github.com/Z3Prover/z3/pull/6048#discussion_r883391669
// TODO(ritave): Add an error handler
// TODO(ritave): Add support for building faster floats without support for Safari
// TODO(ritave): Use Z3_DECLARE_CLOSURE macro to generate code https://github.com/Z3Prover/z3/pull/6048#discussion_r884155462
// TODO(ritave): Add pretty printing
// TODO(ritave): Make Z3 multi-threaded
// TODO(ritave): If a test times out, jest kills it, and the global state of Z3 is left in an unexpected state.
//               This occurs specifically during longer check(). Afterwards, all next tests will fail to run
//               thinking the previous call was not finished. Find a way to stop execution and clean up the global state
const async_mutex_1 = require("async-mutex");
const low_level_1 = require("../low-level");
const types_1 = require("./types");
const utils_1 = require("./utils");
const FALLBACK_PRECISION = 17;
const asyncMutex = new async_mutex_1.Mutex();
function isCoercibleRational(obj) {
    // prettier-ignore
    const r = ((obj !== null &&
        (typeof obj === 'object' || typeof obj === 'function')) &&
        (obj.numerator !== null &&
            (typeof obj.numerator === 'number' || typeof obj.numerator === 'bigint')) &&
        (obj.denominator !== null &&
            (typeof obj.denominator === 'number' || typeof obj.denominator === 'bigint')));
    r &&
        (0, utils_1.assert)((typeof obj.numerator !== 'number' || Number.isSafeInteger(obj.numerator)) &&
            (typeof obj.denominator !== 'number' || Number.isSafeInteger(obj.denominator)), 'Fraction numerator and denominator must be integers');
    return r;
}
function createApi(Z3) {
    // TODO(ritave): Create a custom linting rule that checks if the provided callbacks to cleanup
    //               Don't capture `this`
    const cleanup = new FinalizationRegistry(callback => callback());
    function enableTrace(tag) {
        Z3.enable_trace(tag);
    }
    function disableTrace(tag) {
        Z3.disable_trace(tag);
    }
    function getVersion() {
        return Z3.get_version();
    }
    function getVersionString() {
        const { major, minor, build_number } = Z3.get_version();
        return `${major}.${minor}.${build_number}`;
    }
    function getFullVersion() {
        return Z3.get_full_version();
    }
    function openLog(filename) {
        return Z3.open_log(filename);
    }
    function appendLog(s) {
        Z3.append_log(s);
    }
    function setParam(key, value) {
        if (typeof key === 'string') {
            Z3.global_param_set(key, value.toString());
        }
        else {
            (0, utils_1.assert)(value === undefined, "Can't provide a Record and second parameter to set_param at the same time");
            Object.entries(key).forEach(([key, value]) => setParam(key, value));
        }
    }
    function resetParams() {
        Z3.global_param_reset_all();
    }
    function getParam(name) {
        return Z3.global_param_get(name);
    }
    function createContext(name, options) {
        const cfg = Z3.mk_config();
        if (options != null) {
            Object.entries(options).forEach(([key, value]) => check(Z3.set_param_value(cfg, key, value.toString())));
        }
        const contextPtr = Z3.mk_context_rc(cfg);
        Z3.set_ast_print_mode(contextPtr, low_level_1.Z3_ast_print_mode.Z3_PRINT_SMTLIB2_COMPLIANT);
        Z3.del_config(cfg);
        function _assertContext(...ctxs) {
            ctxs.forEach(other => (0, utils_1.assert)('ctx' in other ? ctx === other.ctx : ctx === other, 'Context mismatch'));
        }
        function _assertPtr(ptr) {
            if (ptr == null)
                throw new TypeError('Expected non-null pointer');
        }
        // call this after every nontrivial call to the underlying API
        function throwIfError() {
            if (Z3.get_error_code(contextPtr) !== low_level_1.Z3_error_code.Z3_OK) {
                throw new Error(Z3.get_error_msg(ctx.ptr, Z3.get_error_code(ctx.ptr)));
            }
        }
        function check(val) {
            throwIfError();
            return val;
        }
        /////////////
        // Private //
        /////////////
        function _toSymbol(s) {
            if (typeof s === 'number') {
                return check(Z3.mk_int_symbol(contextPtr, s));
            }
            else {
                return check(Z3.mk_string_symbol(contextPtr, s));
            }
        }
        function _fromSymbol(sym) {
            const kind = check(Z3.get_symbol_kind(contextPtr, sym));
            switch (kind) {
                case low_level_1.Z3_symbol_kind.Z3_INT_SYMBOL:
                    return Z3.get_symbol_int(contextPtr, sym);
                case low_level_1.Z3_symbol_kind.Z3_STRING_SYMBOL:
                    return Z3.get_symbol_string(contextPtr, sym);
                default:
                    (0, utils_1.assertExhaustive)(kind);
            }
        }
        function _toParams(key, value) {
            const params = Z3.mk_params(contextPtr);
            Z3.params_inc_ref(contextPtr, params);
            // If value is a boolean
            if (typeof value === 'boolean') {
                Z3.params_set_bool(contextPtr, params, _toSymbol(key), value);
            }
            else if (typeof value === 'number') {
                // If value is a uint
                if (Number.isInteger(value)) {
                    check(Z3.params_set_uint(contextPtr, params, _toSymbol(key), value));
                }
                else {
                    // If value is a double
                    check(Z3.params_set_double(contextPtr, params, _toSymbol(key), value));
                }
            }
            else if (typeof value === 'string') {
                check(Z3.params_set_symbol(contextPtr, params, _toSymbol(key), _toSymbol(value)));
            }
            return params;
        }
        function _toAst(ast) {
            switch (check(Z3.get_ast_kind(contextPtr, ast))) {
                case low_level_1.Z3_ast_kind.Z3_SORT_AST:
                    return _toSort(ast);
                case low_level_1.Z3_ast_kind.Z3_FUNC_DECL_AST:
                    return new FuncDeclImpl(ast);
                default:
                    return _toExpr(ast);
            }
        }
        function _toSort(ast) {
            switch (check(Z3.get_sort_kind(contextPtr, ast))) {
                case low_level_1.Z3_sort_kind.Z3_BOOL_SORT:
                    return new BoolSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_INT_SORT:
                case low_level_1.Z3_sort_kind.Z3_REAL_SORT:
                    return new ArithSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_BV_SORT:
                    return new BitVecSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_FLOATING_POINT_SORT:
                    return new FPSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_ROUNDING_MODE_SORT:
                    return new FPRMSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_SEQ_SORT:
                    return new SeqSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_RE_SORT:
                    return new ReSortImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_ARRAY_SORT:
                    return new ArraySortImpl(ast);
                default:
                    return new SortImpl(ast);
            }
        }
        function _toExpr(ast) {
            const kind = check(Z3.get_ast_kind(contextPtr, ast));
            if (kind === low_level_1.Z3_ast_kind.Z3_QUANTIFIER_AST) {
                if (Z3.is_lambda(contextPtr, ast)) {
                    return new LambdaImpl(ast);
                }
                return new NonLambdaQuantifierImpl(ast);
            }
            const sortKind = check(Z3.get_sort_kind(contextPtr, Z3.get_sort(contextPtr, ast)));
            switch (sortKind) {
                case low_level_1.Z3_sort_kind.Z3_BOOL_SORT:
                    return new BoolImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_INT_SORT:
                    if (kind === low_level_1.Z3_ast_kind.Z3_NUMERAL_AST) {
                        return new IntNumImpl(ast);
                    }
                    return new ArithImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_REAL_SORT:
                    if (kind === low_level_1.Z3_ast_kind.Z3_NUMERAL_AST) {
                        return new RatNumImpl(ast);
                    }
                    return new ArithImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_BV_SORT:
                    if (kind === low_level_1.Z3_ast_kind.Z3_NUMERAL_AST) {
                        return new BitVecNumImpl(ast);
                    }
                    return new BitVecImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_FLOATING_POINT_SORT:
                    if (kind === low_level_1.Z3_ast_kind.Z3_NUMERAL_AST || kind === low_level_1.Z3_ast_kind.Z3_APP_AST) {
                        return new FPNumImpl(ast);
                    }
                    return new FPImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_ROUNDING_MODE_SORT:
                    return new FPRMImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_SEQ_SORT:
                    return new SeqImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_RE_SORT:
                    return new ReImpl(ast);
                case low_level_1.Z3_sort_kind.Z3_ARRAY_SORT:
                    return new ArrayImpl(ast);
                default:
                    return new ExprImpl(ast);
            }
        }
        function _flattenArgs(args) {
            const result = [];
            for (const arg of args) {
                if (isAstVector(arg)) {
                    result.push(...arg.values());
                }
                else {
                    result.push(arg);
                }
            }
            return result;
        }
        function _toProbe(p) {
            if (isProbe(p)) {
                return p;
            }
            return new ProbeImpl(p);
        }
        function _probeNary(f, args) {
            (0, utils_1.assert)(args.length > 0, 'At least one argument expected');
            let r = _toProbe(args[0]);
            for (let i = 1; i < args.length; i++) {
                r = new ProbeImpl(check(f(contextPtr, r.ptr, _toProbe(args[i]).ptr)));
            }
            return r;
        }
        ///////////////
        // Functions //
        ///////////////
        function interrupt() {
            check(Z3.interrupt(contextPtr));
        }
        function setPrintMode(mode) {
            Z3.set_ast_print_mode(contextPtr, mode);
        }
        function isModel(obj) {
            const r = obj instanceof ModelImpl;
            r && _assertContext(obj);
            return r;
        }
        function isAst(obj) {
            const r = obj instanceof AstImpl;
            r && _assertContext(obj);
            return r;
        }
        function isSort(obj) {
            const r = obj instanceof SortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFuncDecl(obj) {
            const r = obj instanceof FuncDeclImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFuncInterp(obj) {
            const r = obj instanceof FuncInterpImpl;
            r && _assertContext(obj);
            return r;
        }
        function isApp(obj) {
            if (!isExpr(obj)) {
                return false;
            }
            const kind = check(Z3.get_ast_kind(contextPtr, obj.ast));
            return kind === low_level_1.Z3_ast_kind.Z3_NUMERAL_AST || kind === low_level_1.Z3_ast_kind.Z3_APP_AST;
        }
        function isConst(obj) {
            return isExpr(obj) && isApp(obj) && obj.numArgs() === 0;
        }
        function isExpr(obj) {
            const r = obj instanceof ExprImpl;
            r && _assertContext(obj);
            return r;
        }
        function isVar(obj) {
            return isExpr(obj) && check(Z3.get_ast_kind(contextPtr, obj.ast)) === low_level_1.Z3_ast_kind.Z3_VAR_AST;
        }
        function isAppOf(obj, kind) {
            return isExpr(obj) && isApp(obj) && obj.decl().kind() === kind;
        }
        function isBool(obj) {
            const r = obj instanceof ExprImpl && obj.sort.kind() === low_level_1.Z3_sort_kind.Z3_BOOL_SORT;
            r && _assertContext(obj);
            return r;
        }
        function isTrue(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_TRUE);
        }
        function isFalse(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_FALSE);
        }
        function isAnd(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_AND);
        }
        function isOr(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_OR);
        }
        function isImplies(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_IMPLIES);
        }
        function isNot(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_NOT);
        }
        function isEq(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_EQ);
        }
        function isDistinct(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_DISTINCT);
        }
        function isQuantifier(obj) {
            const r = obj instanceof QuantifierImpl;
            r && _assertContext(obj);
            return r;
        }
        function isArith(obj) {
            const r = obj instanceof ArithImpl;
            r && _assertContext(obj);
            return r;
        }
        function isArithSort(obj) {
            const r = obj instanceof ArithSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isInt(obj) {
            return isArith(obj) && isIntSort(obj.sort);
        }
        function isIntVal(obj) {
            const r = obj instanceof IntNumImpl;
            r && _assertContext(obj);
            return r;
        }
        function isIntSort(obj) {
            return isSort(obj) && obj.kind() === low_level_1.Z3_sort_kind.Z3_INT_SORT;
        }
        function isReal(obj) {
            return isArith(obj) && isRealSort(obj.sort);
        }
        function isRealVal(obj) {
            const r = obj instanceof RatNumImpl;
            r && _assertContext(obj);
            return r;
        }
        function isRealSort(obj) {
            return isSort(obj) && obj.kind() === low_level_1.Z3_sort_kind.Z3_REAL_SORT;
        }
        function isRCFNum(obj) {
            const r = obj instanceof RCFNumImpl;
            r && _assertContext(obj);
            return r;
        }
        function isBitVecSort(obj) {
            const r = obj instanceof BitVecSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isBitVec(obj) {
            const r = obj instanceof BitVecImpl;
            r && _assertContext(obj);
            return r;
        }
        function isBitVecVal(obj) {
            const r = obj instanceof BitVecNumImpl;
            r && _assertContext(obj);
            return r;
        }
        function isArraySort(obj) {
            const r = obj instanceof ArraySortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isArray(obj) {
            const r = obj instanceof ArrayImpl;
            r && _assertContext(obj);
            return r;
        }
        function isConstArray(obj) {
            return isAppOf(obj, low_level_1.Z3_decl_kind.Z3_OP_CONST_ARRAY);
        }
        function isFPRMSort(obj) {
            const r = obj instanceof FPRMSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFPRM(obj) {
            const r = obj instanceof FPRMImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFPSort(obj) {
            const r = obj instanceof FPSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFP(obj) {
            const r = obj instanceof FPImpl;
            r && _assertContext(obj);
            return r;
        }
        function isFPVal(obj) {
            const r = obj instanceof FPNumImpl;
            r && _assertContext(obj);
            return r;
        }
        function isSeqSort(obj) {
            const r = obj instanceof SeqSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isSeq(obj) {
            const r = obj instanceof SeqImpl;
            r && _assertContext(obj);
            return r;
        }
        function isReSort(obj) {
            const r = obj instanceof ReSortImpl;
            r && _assertContext(obj);
            return r;
        }
        function isRe(obj) {
            const r = obj instanceof ReImpl;
            r && _assertContext(obj);
            return r;
        }
        function isStringSort(obj) {
            return isSeqSort(obj) && obj.isString();
        }
        function isString(obj) {
            return isSeq(obj) && obj.isString();
        }
        function isProbe(obj) {
            const r = obj instanceof ProbeImpl;
            r && _assertContext(obj);
            return r;
        }
        function isTactic(obj) {
            const r = obj instanceof TacticImpl;
            r && _assertContext(obj);
            return r;
        }
        function isGoal(obj) {
            const r = obj instanceof GoalImpl;
            r && _assertContext(obj);
            return r;
        }
        function isAstVector(obj) {
            const r = obj instanceof AstVectorImpl;
            r && _assertContext(obj);
            return r;
        }
        function eqIdentity(a, b) {
            return a.eqIdentity(b);
        }
        function getVarIndex(obj) {
            (0, utils_1.assert)(isVar(obj), 'Z3 bound variable expected');
            return Z3.get_index_value(contextPtr, obj.ast);
        }
        function from(value) {
            if (typeof value === 'boolean') {
                return Bool.val(value);
            }
            else if (typeof value === 'number') {
                if (!Number.isFinite(value)) {
                    throw new Error(`cannot represent infinity/NaN (got ${value})`);
                }
                if (Math.floor(value) === value) {
                    return Int.val(value);
                }
                return Real.val(value);
            }
            else if (isCoercibleRational(value)) {
                return Real.val(value);
            }
            else if (typeof value === 'bigint') {
                return Int.val(value);
            }
            else if (isExpr(value)) {
                return value;
            }
            (0, utils_1.assert)(false);
        }
        async function solve(...assertions) {
            const solver = new ctx.Solver();
            solver.add(...assertions);
            const result = await solver.check();
            if (result === 'sat') {
                return solver.model();
            }
            return result;
        }
        ///////////////////////////////
        // expression simplification //
        ///////////////////////////////
        async function simplify(e) {
            const result = await Z3.simplify(contextPtr, e.ast);
            return _toExpr(check(result));
        }
        /////////////
        // Objects //
        /////////////
        const Sort = {
            declare: (name) => new SortImpl(Z3.mk_uninterpreted_sort(contextPtr, _toSymbol(name))),
        };
        const Function = {
            declare: (name, ...signature) => {
                const arity = signature.length - 1;
                const rng = signature[arity];
                _assertContext(rng);
                const dom = [];
                for (let i = 0; i < arity; i++) {
                    _assertContext(signature[i]);
                    dom.push(signature[i].ptr);
                }
                return new FuncDeclImpl(Z3.mk_func_decl(contextPtr, _toSymbol(name), dom, rng.ptr));
            },
            fresh: (...signature) => {
                const arity = signature.length - 1;
                const rng = signature[arity];
                _assertContext(rng);
                const dom = [];
                for (let i = 0; i < arity; i++) {
                    _assertContext(signature[i]);
                    dom.push(signature[i].ptr);
                }
                return new FuncDeclImpl(Z3.mk_fresh_func_decl(contextPtr, 'f', dom, rng.ptr));
            },
        };
        const RecFunc = {
            declare: (name, ...signature) => {
                const arity = signature.length - 1;
                const rng = signature[arity];
                _assertContext(rng);
                const dom = [];
                for (let i = 0; i < arity; i++) {
                    _assertContext(signature[i]);
                    dom.push(signature[i].ptr);
                }
                return new FuncDeclImpl(Z3.mk_rec_func_decl(contextPtr, _toSymbol(name), dom, rng.ptr));
            },
            addDefinition: (f, args, body) => {
                _assertContext(f, ...args, body);
                check(Z3.add_rec_def(contextPtr, f.ptr, args.map(arg => arg.ast), body.ast));
            },
        };
        const Bool = {
            sort: () => new BoolSortImpl(Z3.mk_bool_sort(contextPtr)),
            const: (name) => new BoolImpl(Z3.mk_const(contextPtr, _toSymbol(name), Bool.sort().ptr)),
            consts: (names) => {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Bool.const(name));
            },
            vector: (prefix, count) => {
                const result = [];
                for (let i = 0; i < count; i++) {
                    result.push(Bool.const(`${prefix}__${i}`));
                }
                return result;
            },
            fresh: (prefix = 'b') => new BoolImpl(Z3.mk_fresh_const(contextPtr, prefix, Bool.sort().ptr)),
            val: (value) => {
                if (value) {
                    return new BoolImpl(Z3.mk_true(contextPtr));
                }
                return new BoolImpl(Z3.mk_false(contextPtr));
            },
        };
        const Int = {
            sort: () => new ArithSortImpl(Z3.mk_int_sort(contextPtr)),
            const: (name) => new ArithImpl(Z3.mk_const(contextPtr, _toSymbol(name), Int.sort().ptr)),
            consts: (names) => {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Int.const(name));
            },
            vector: (prefix, count) => {
                const result = [];
                for (let i = 0; i < count; i++) {
                    result.push(Int.const(`${prefix}__${i}`));
                }
                return result;
            },
            fresh: (prefix = 'x') => new ArithImpl(Z3.mk_fresh_const(contextPtr, prefix, Int.sort().ptr)),
            val: (value) => {
                (0, utils_1.assert)(typeof value === 'bigint' || typeof value === 'string' || Number.isSafeInteger(value));
                return new IntNumImpl(check(Z3.mk_numeral(contextPtr, value.toString(), Int.sort().ptr)));
            },
        };
        const Real = {
            sort: () => new ArithSortImpl(Z3.mk_real_sort(contextPtr)),
            const: (name) => new ArithImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), Real.sort().ptr))),
            consts: (names) => {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Real.const(name));
            },
            vector: (prefix, count) => {
                const result = [];
                for (let i = 0; i < count; i++) {
                    result.push(Real.const(`${prefix}__${i}`));
                }
                return result;
            },
            fresh: (prefix = 'b') => new ArithImpl(Z3.mk_fresh_const(contextPtr, prefix, Real.sort().ptr)),
            val: (value) => {
                if (isCoercibleRational(value)) {
                    value = `${value.numerator}/${value.denominator}`;
                }
                return new RatNumImpl(Z3.mk_numeral(contextPtr, value.toString(), Real.sort().ptr));
            },
        };
        const RCFNum = Object.assign((value) => new RCFNumImpl(value), {
            pi: () => new RCFNumImpl(check(Z3.rcf_mk_pi(contextPtr))),
            e: () => new RCFNumImpl(check(Z3.rcf_mk_e(contextPtr))),
            infinitesimal: () => new RCFNumImpl(check(Z3.rcf_mk_infinitesimal(contextPtr))),
            roots: (coefficients) => {
                (0, utils_1.assert)(coefficients.length > 0, 'Polynomial coefficients cannot be empty');
                const coeffPtrs = coefficients.map(c => c.ptr);
                const { rv: numRoots, roots: rootPtrs } = Z3.rcf_mk_roots(contextPtr, coeffPtrs);
                const result = [];
                for (let i = 0; i < numRoots; i++) {
                    result.push(new RCFNumImpl(rootPtrs[i]));
                }
                return result;
            },
        });
        const BitVec = {
            sort(bits) {
                (0, utils_1.assert)(Number.isSafeInteger(bits), 'number of bits must be an integer');
                return new BitVecSortImpl(Z3.mk_bv_sort(contextPtr, bits));
            },
            const(name, bits) {
                return new BitVecImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), isBitVecSort(bits) ? bits.ptr : BitVec.sort(bits).ptr)));
            },
            consts(names, bits) {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => BitVec.const(name, bits));
            },
            val(value, bits) {
                if (value === true) {
                    return BitVec.val(1, bits);
                }
                else if (value === false) {
                    return BitVec.val(0, bits);
                }
                return new BitVecNumImpl(check(Z3.mk_numeral(contextPtr, value.toString(), isBitVecSort(bits) ? bits.ptr : BitVec.sort(bits).ptr)));
            },
        };
        const Float = {
            sort(ebits, sbits) {
                (0, utils_1.assert)(Number.isSafeInteger(ebits) && ebits > 0, 'ebits must be a positive integer');
                (0, utils_1.assert)(Number.isSafeInteger(sbits) && sbits > 0, 'sbits must be a positive integer');
                return new FPSortImpl(Z3.mk_fpa_sort(contextPtr, ebits, sbits));
            },
            sort16() {
                return new FPSortImpl(Z3.mk_fpa_sort_16(contextPtr));
            },
            sort32() {
                return new FPSortImpl(Z3.mk_fpa_sort_32(contextPtr));
            },
            sort64() {
                return new FPSortImpl(Z3.mk_fpa_sort_64(contextPtr));
            },
            sort128() {
                return new FPSortImpl(Z3.mk_fpa_sort_128(contextPtr));
            },
            const(name, sort) {
                return new FPImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), sort.ptr)));
            },
            consts(names, sort) {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Float.const(name, sort));
            },
            val(value, sort) {
                return new FPNumImpl(check(Z3.mk_fpa_numeral_double(contextPtr, value, sort.ptr)));
            },
            NaN(sort) {
                return new FPNumImpl(check(Z3.mk_fpa_nan(contextPtr, sort.ptr)));
            },
            inf(sort, negative = false) {
                return new FPNumImpl(check(Z3.mk_fpa_inf(contextPtr, sort.ptr, negative)));
            },
            zero(sort, negative = false) {
                return new FPNumImpl(check(Z3.mk_fpa_zero(contextPtr, sort.ptr, negative)));
            },
        };
        const FloatRM = {
            sort() {
                return new FPRMSortImpl(Z3.mk_fpa_rounding_mode_sort(contextPtr));
            },
            RNE() {
                return new FPRMImpl(check(Z3.mk_fpa_rne(contextPtr)));
            },
            RNA() {
                return new FPRMImpl(check(Z3.mk_fpa_rna(contextPtr)));
            },
            RTP() {
                return new FPRMImpl(check(Z3.mk_fpa_rtp(contextPtr)));
            },
            RTN() {
                return new FPRMImpl(check(Z3.mk_fpa_rtn(contextPtr)));
            },
            RTZ() {
                return new FPRMImpl(check(Z3.mk_fpa_rtz(contextPtr)));
            },
        };
        const String = {
            sort() {
                return new SeqSortImpl(Z3.mk_string_sort(contextPtr));
            },
            const(name) {
                return new SeqImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), String.sort().ptr)));
            },
            consts(names) {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => String.const(name));
            },
            val(value) {
                return new SeqImpl(check(Z3.mk_string(contextPtr, value)));
            },
        };
        const Seq = {
            sort(elemSort) {
                return new SeqSortImpl(Z3.mk_seq_sort(contextPtr, elemSort.ptr));
            },
            empty(elemSort) {
                return new SeqImpl(check(Z3.mk_seq_empty(contextPtr, Seq.sort(elemSort).ptr)));
            },
            unit(elem) {
                return new SeqImpl(check(Z3.mk_seq_unit(contextPtr, elem.ast)));
            },
        };
        const Re = {
            sort(seqSort) {
                return new ReSortImpl(Z3.mk_re_sort(contextPtr, seqSort.ptr));
            },
            toRe(seq) {
                const seqExpr = isSeq(seq) ? seq : String.val(seq);
                return new ReImpl(check(Z3.mk_seq_to_re(contextPtr, seqExpr.ast)));
            },
        };
        const Array = {
            sort(...sig) {
                const arity = sig.length - 1;
                const r = sig[arity];
                const d = sig[0];
                if (arity === 1) {
                    return new ArraySortImpl(Z3.mk_array_sort(contextPtr, d.ptr, r.ptr));
                }
                const dom = sig.slice(0, arity);
                return new ArraySortImpl(Z3.mk_array_sort_n(contextPtr, dom.map(s => s.ptr), r.ptr));
            },
            const(name, ...sig) {
                return new ArrayImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), Array.sort(...sig).ptr)));
            },
            consts(names, ...sig) {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Array.const(name, ...sig));
            },
            K(domain, value) {
                return new ArrayImpl(check(Z3.mk_const_array(contextPtr, domain.ptr, value.ptr)));
            },
        };
        const Set = {
            // reference: https://z3prover.github.io/api/html/namespacez3py.html#a545f894afeb24caa1b88b7f2a324ee7e
            sort(sort) {
                return Array.sort(sort, Bool.sort());
            },
            const(name, sort) {
                return new SetImpl(check(Z3.mk_const(contextPtr, _toSymbol(name), Array.sort(sort, Bool.sort()).ptr)));
            },
            consts(names, sort) {
                if (typeof names === 'string') {
                    names = names.split(' ');
                }
                return names.map(name => Set.const(name, sort));
            },
            empty(sort) {
                return EmptySet(sort);
            },
            val(values, sort) {
                var result = EmptySet(sort);
                for (const value of values) {
                    result = SetAdd(result, value);
                }
                return result;
            },
        };
        const Datatype = Object.assign((name) => {
            return new DatatypeImpl(ctx, name);
        }, {
            createDatatypes(...datatypes) {
                return createDatatypes(...datatypes);
            },
        });
        function If(condition, onTrue, onFalse) {
            if (isProbe(condition) && isTactic(onTrue) && isTactic(onFalse)) {
                return Cond(condition, onTrue, onFalse);
            }
            (0, utils_1.assert)(!isProbe(condition) && !isTactic(onTrue) && !isTactic(onFalse), 'Mixed expressions and goals');
            if (typeof condition === 'boolean') {
                condition = Bool.val(condition);
            }
            onTrue = from(onTrue);
            onFalse = from(onFalse);
            return _toExpr(check(Z3.mk_ite(contextPtr, condition.ptr, onTrue.ast, onFalse.ast)));
        }
        function Distinct(...exprs) {
            (0, utils_1.assert)(exprs.length > 0, "Can't make Distinct ouf of nothing");
            return new BoolImpl(check(Z3.mk_distinct(contextPtr, exprs.map(expr => {
                expr = from(expr);
                _assertContext(expr);
                return expr.ast;
            }))));
        }
        function Const(name, sort) {
            _assertContext(sort);
            return _toExpr(check(Z3.mk_const(contextPtr, _toSymbol(name), sort.ptr)));
        }
        function Consts(names, sort) {
            _assertContext(sort);
            if (typeof names === 'string') {
                names = names.split(' ');
            }
            return names.map(name => Const(name, sort));
        }
        function FreshConst(sort, prefix = 'c') {
            _assertContext(sort);
            return _toExpr(Z3.mk_fresh_const(sort.ctx.ptr, prefix, sort.ptr));
        }
        function Var(idx, sort) {
            _assertContext(sort);
            return _toExpr(Z3.mk_bound(sort.ctx.ptr, idx, sort.ptr));
        }
        function Implies(a, b) {
            a = from(a);
            b = from(b);
            _assertContext(a, b);
            return new BoolImpl(check(Z3.mk_implies(contextPtr, a.ptr, b.ptr)));
        }
        function Iff(a, b) {
            a = from(a);
            b = from(b);
            _assertContext(a, b);
            return new BoolImpl(check(Z3.mk_iff(contextPtr, a.ptr, b.ptr)));
        }
        function Eq(a, b) {
            a = from(a);
            b = from(b);
            _assertContext(a, b);
            return a.eq(b);
        }
        function Xor(a, b) {
            a = from(a);
            b = from(b);
            _assertContext(a, b);
            return new BoolImpl(check(Z3.mk_xor(contextPtr, a.ptr, b.ptr)));
        }
        function Not(a) {
            if (typeof a === 'boolean') {
                a = from(a);
            }
            _assertContext(a);
            if (isProbe(a)) {
                return new ProbeImpl(check(Z3.probe_not(contextPtr, a.ptr)));
            }
            return new BoolImpl(check(Z3.mk_not(contextPtr, a.ptr)));
        }
        function And(...args) {
            if (args.length == 1 && args[0] instanceof ctx.AstVector) {
                args = [...args[0].values()];
                (0, utils_1.assert)((0, utils_1.allSatisfy)(args, isBool) ?? true, 'AstVector containing not bools');
            }
            const allProbes = (0, utils_1.allSatisfy)(args, isProbe) ?? false;
            if (allProbes) {
                return _probeNary(Z3.probe_and, args);
            }
            else {
                const castArgs = args.map(from);
                _assertContext(...castArgs);
                return new BoolImpl(check(Z3.mk_and(contextPtr, castArgs.map(arg => arg.ptr))));
            }
        }
        function Or(...args) {
            if (args.length == 1 && args[0] instanceof ctx.AstVector) {
                args = [...args[0].values()];
                (0, utils_1.assert)((0, utils_1.allSatisfy)(args, isBool) ?? true, 'AstVector containing not bools');
            }
            const allProbes = (0, utils_1.allSatisfy)(args, isProbe) ?? false;
            if (allProbes) {
                return _probeNary(Z3.probe_or, args);
            }
            else {
                const castArgs = args.map(from);
                _assertContext(...castArgs);
                return new BoolImpl(check(Z3.mk_or(contextPtr, castArgs.map(arg => arg.ptr))));
            }
        }
        function PbEq(args, coeffs, k) {
            _assertContext(...args);
            if (args.length !== coeffs.length) {
                throw new Error('Number of arguments and coefficients must match');
            }
            return new BoolImpl(check(Z3.mk_pbeq(contextPtr, args.map(arg => arg.ast), coeffs, k)));
        }
        function PbGe(args, coeffs, k) {
            _assertContext(...args);
            if (args.length !== coeffs.length) {
                throw new Error('Number of arguments and coefficients must match');
            }
            return new BoolImpl(check(Z3.mk_pbge(contextPtr, args.map(arg => arg.ast), coeffs, k)));
        }
        function PbLe(args, coeffs, k) {
            _assertContext(...args);
            if (args.length !== coeffs.length) {
                throw new Error('Number of arguments and coefficients must match');
            }
            return new BoolImpl(check(Z3.mk_pble(contextPtr, args.map(arg => arg.ast), coeffs, k)));
        }
        function AtMost(args, k) {
            _assertContext(...args);
            return new BoolImpl(check(Z3.mk_atmost(contextPtr, args.map(arg => arg.ast), k)));
        }
        function AtLeast(args, k) {
            _assertContext(...args);
            return new BoolImpl(check(Z3.mk_atleast(contextPtr, args.map(arg => arg.ast), k)));
        }
        function ForAll(quantifiers, body, weight = 1) {
            // Verify all quantifiers are constants
            if (!(0, utils_1.allSatisfy)(quantifiers, isConst)) {
                throw new Error('Quantifier variables must be constants');
            }
            return new NonLambdaQuantifierImpl(check(Z3.mk_quantifier_const_ex(contextPtr, true, weight, _toSymbol(''), _toSymbol(''), quantifiers.map(q => q.ptr), // The earlier check verifies these are all apps
            [], [], body.ptr)));
        }
        function Exists(quantifiers, body, weight = 1) {
            // Verify all quantifiers are constants
            if (!(0, utils_1.allSatisfy)(quantifiers, isConst)) {
                throw new Error('Quantifier variables must be constants');
            }
            return new NonLambdaQuantifierImpl(check(Z3.mk_quantifier_const_ex(contextPtr, false, weight, _toSymbol(''), _toSymbol(''), quantifiers.map(q => q.ptr), // The earlier check verifies these are all apps
            [], [], body.ptr)));
        }
        function Lambda(quantifiers, expr) {
            // TODO(walden): For some reason LambdaImpl<DomainSort, RangeSort> leads to type issues
            //    and Typescript won't build. I'm not sure why since the types seem to all match
            //    up. For now, we just use any for the domain sort
            // Verify all quantifiers are constants
            if (!(0, utils_1.allSatisfy)(quantifiers, isConst)) {
                throw new Error('Quantifier variables must be constants');
            }
            return new LambdaImpl(check(Z3.mk_lambda_const(contextPtr, quantifiers.map(q => q.ptr), expr.ptr)));
        }
        function ToReal(expr) {
            expr = from(expr);
            _assertContext(expr);
            (0, utils_1.assert)(isInt(expr), 'Int expression expected');
            return new ArithImpl(check(Z3.mk_int2real(contextPtr, expr.ast)));
        }
        function ToInt(expr) {
            if (!isExpr(expr)) {
                expr = Real.val(expr);
            }
            _assertContext(expr);
            (0, utils_1.assert)(isReal(expr), 'Real expression expected');
            return new ArithImpl(check(Z3.mk_real2int(contextPtr, expr.ast)));
        }
        function IsInt(expr) {
            if (!isExpr(expr)) {
                expr = Real.val(expr);
            }
            _assertContext(expr);
            (0, utils_1.assert)(isReal(expr), 'Real expression expected');
            return new BoolImpl(check(Z3.mk_is_int(contextPtr, expr.ast)));
        }
        function Sqrt(a) {
            if (!isExpr(a)) {
                a = Real.val(a);
            }
            return a.pow('1/2');
        }
        function Cbrt(a) {
            if (!isExpr(a)) {
                a = Real.val(a);
            }
            return a.pow('1/3');
        }
        function BV2Int(a, isSigned) {
            _assertContext(a);
            return new ArithImpl(check(Z3.mk_bv2int(contextPtr, a.ast, isSigned)));
        }
        function Int2BV(a, bits) {
            if (isArith(a)) {
                (0, utils_1.assert)(isInt(a), 'parameter must be an integer');
            }
            else {
                (0, utils_1.assert)(typeof a !== 'number' || Number.isSafeInteger(a), 'parameter must not have decimal places');
                a = Int.val(a);
            }
            return new BitVecImpl(check(Z3.mk_int2bv(contextPtr, bits, a.ast)));
        }
        function Concat(...bitvecs) {
            _assertContext(...bitvecs);
            return bitvecs.reduce((prev, curr) => new BitVecImpl(check(Z3.mk_concat(contextPtr, prev.ast, curr.ast))));
        }
        function Cond(probe, onTrue, onFalse) {
            _assertContext(probe, onTrue, onFalse);
            return new TacticImpl(check(Z3.tactic_cond(contextPtr, probe.ptr, onTrue.ptr, onFalse.ptr)));
        }
        function _toTactic(t) {
            return typeof t === 'string' ? new TacticImpl(t) : t;
        }
        function AndThen(t1, t2, ...ts) {
            let result = _toTactic(t1);
            let current = _toTactic(t2);
            _assertContext(result, current);
            result = new TacticImpl(check(Z3.tactic_and_then(contextPtr, result.ptr, current.ptr)));
            for (const t of ts) {
                current = _toTactic(t);
                _assertContext(result, current);
                result = new TacticImpl(check(Z3.tactic_and_then(contextPtr, result.ptr, current.ptr)));
            }
            return result;
        }
        function OrElse(t1, t2, ...ts) {
            let result = _toTactic(t1);
            let current = _toTactic(t2);
            _assertContext(result, current);
            result = new TacticImpl(check(Z3.tactic_or_else(contextPtr, result.ptr, current.ptr)));
            for (const t of ts) {
                current = _toTactic(t);
                _assertContext(result, current);
                result = new TacticImpl(check(Z3.tactic_or_else(contextPtr, result.ptr, current.ptr)));
            }
            return result;
        }
        const UINT_MAX = 4294967295;
        function Repeat(t, max) {
            const tactic = _toTactic(t);
            _assertContext(tactic);
            const maxVal = max !== undefined ? max : UINT_MAX;
            return new TacticImpl(check(Z3.tactic_repeat(contextPtr, tactic.ptr, maxVal)));
        }
        function TryFor(t, ms) {
            const tactic = _toTactic(t);
            _assertContext(tactic);
            return new TacticImpl(check(Z3.tactic_try_for(contextPtr, tactic.ptr, ms)));
        }
        function When(p, t) {
            const tactic = _toTactic(t);
            _assertContext(p, tactic);
            return new TacticImpl(check(Z3.tactic_when(contextPtr, p.ptr, tactic.ptr)));
        }
        function Skip() {
            return new TacticImpl(check(Z3.tactic_skip(contextPtr)));
        }
        function Fail() {
            return new TacticImpl(check(Z3.tactic_fail(contextPtr)));
        }
        function FailIf(p) {
            _assertContext(p);
            return new TacticImpl(check(Z3.tactic_fail_if(contextPtr, p.ptr)));
        }
        function ParOr(...tactics) {
            (0, utils_1.assert)(tactics.length > 0, 'ParOr requires at least one tactic');
            const tacticImpls = tactics.map(t => _toTactic(t));
            _assertContext(...tacticImpls);
            const tacticPtrs = tacticImpls.map(t => t.ptr);
            return new TacticImpl(check(Z3.tactic_par_or(contextPtr, tacticPtrs)));
        }
        function ParAndThen(t1, t2) {
            const tactic1 = _toTactic(t1);
            const tactic2 = _toTactic(t2);
            _assertContext(tactic1, tactic2);
            return new TacticImpl(check(Z3.tactic_par_and_then(contextPtr, tactic1.ptr, tactic2.ptr)));
        }
        function With(t, params) {
            const tactic = _toTactic(t);
            _assertContext(tactic);
            // Convert params to Z3_params
            const z3params = check(Z3.mk_params(contextPtr));
            Z3.params_inc_ref(contextPtr, z3params);
            try {
                for (const [key, value] of Object.entries(params)) {
                    const sym = _toSymbol(key);
                    if (typeof value === 'boolean') {
                        Z3.params_set_bool(contextPtr, z3params, sym, value);
                    }
                    else if (typeof value === 'number') {
                        if (Number.isInteger(value)) {
                            Z3.params_set_uint(contextPtr, z3params, sym, value);
                        }
                        else {
                            Z3.params_set_double(contextPtr, z3params, sym, value);
                        }
                    }
                    else if (typeof value === 'string') {
                        Z3.params_set_symbol(contextPtr, z3params, sym, _toSymbol(value));
                    }
                    else {
                        throw new Error(`Unsupported parameter type for ${key}`);
                    }
                }
                const result = new TacticImpl(check(Z3.tactic_using_params(contextPtr, tactic.ptr, z3params)));
                return result;
            }
            finally {
                Z3.params_dec_ref(contextPtr, z3params);
            }
        }
        function LT(a, b) {
            return new BoolImpl(check(Z3.mk_lt(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function GT(a, b) {
            return new BoolImpl(check(Z3.mk_gt(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function LE(a, b) {
            return new BoolImpl(check(Z3.mk_le(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function GE(a, b) {
            return new BoolImpl(check(Z3.mk_ge(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function ULT(a, b) {
            return new BoolImpl(check(Z3.mk_bvult(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function UGT(a, b) {
            return new BoolImpl(check(Z3.mk_bvugt(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function ULE(a, b) {
            return new BoolImpl(check(Z3.mk_bvule(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function UGE(a, b) {
            return new BoolImpl(check(Z3.mk_bvuge(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function SLT(a, b) {
            return new BoolImpl(check(Z3.mk_bvslt(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function SGT(a, b) {
            return new BoolImpl(check(Z3.mk_bvsgt(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function SLE(a, b) {
            return new BoolImpl(check(Z3.mk_bvsle(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function SGE(a, b) {
            return new BoolImpl(check(Z3.mk_bvsge(contextPtr, a.ast, a.sort.cast(b).ast)));
        }
        function Extract(hi, lo, val) {
            return new BitVecImpl(check(Z3.mk_extract(contextPtr, hi, lo, val.ast)));
        }
        function Select(array, ...indices) {
            const args = indices.map((arg, i) => array.domain_n(i).cast(arg));
            if (args.length === 1) {
                return _toExpr(check(Z3.mk_select(contextPtr, array.ast, args[0].ast)));
            }
            const _args = args.map(arg => arg.ast);
            return _toExpr(check(Z3.mk_select_n(contextPtr, array.ast, _args)));
        }
        function Store(array, ...indicesAndValue) {
            const args = indicesAndValue.map((arg, i) => {
                if (i === indicesAndValue.length - 1) {
                    return array.range().cast(arg);
                }
                return array.domain_n(i).cast(arg);
            });
            if (args.length <= 1) {
                throw new Error('Array store requires both index and value arguments');
            }
            if (args.length === 2) {
                return _toExpr(check(Z3.mk_store(contextPtr, array.ast, args[0].ast, args[1].ast)));
            }
            const _idxs = args.slice(0, args.length - 1).map(arg => arg.ast);
            return _toExpr(check(Z3.mk_store_n(contextPtr, array.ast, _idxs, args[args.length - 1].ast)));
        }
        /**
         * Create array extensionality index given two arrays with the same sort.
         * The meaning is given by the axiom:
         * (=> (= (select A (array-ext A B)) (select B (array-ext A B))) (= A B))
         * Two arrays are equal if and only if they are equal on the index returned by this function.
         */
        function Ext(a, b) {
            return _toExpr(check(Z3.mk_array_ext(contextPtr, a.ast, b.ast)));
        }
        function SetUnion(...args) {
            return new SetImpl(check(Z3.mk_set_union(contextPtr, args.map(arg => arg.ast))));
        }
        function SetIntersect(...args) {
            return new SetImpl(check(Z3.mk_set_intersect(contextPtr, args.map(arg => arg.ast))));
        }
        function SetDifference(a, b) {
            return new SetImpl(check(Z3.mk_set_difference(contextPtr, a.ast, b.ast)));
        }
        function SetAdd(set, elem) {
            const arg = set.elemSort().cast(elem);
            return new SetImpl(check(Z3.mk_set_add(contextPtr, set.ast, arg.ast)));
        }
        function SetDel(set, elem) {
            const arg = set.elemSort().cast(elem);
            return new SetImpl(check(Z3.mk_set_del(contextPtr, set.ast, arg.ast)));
        }
        function SetComplement(set) {
            return new SetImpl(check(Z3.mk_set_complement(contextPtr, set.ast)));
        }
        function EmptySet(sort) {
            return new SetImpl(check(Z3.mk_empty_set(contextPtr, sort.ptr)));
        }
        function FullSet(sort) {
            return new SetImpl(check(Z3.mk_full_set(contextPtr, sort.ptr)));
        }
        function isMember(elem, set) {
            const arg = set.elemSort().cast(elem);
            return new BoolImpl(check(Z3.mk_set_member(contextPtr, arg.ast, set.ast)));
        }
        function isSubset(a, b) {
            return new BoolImpl(check(Z3.mk_set_subset(contextPtr, a.ast, b.ast)));
        }
        //////////////////////
        // Regular Expressions
        //////////////////////
        function InRe(seq, re) {
            const seqExpr = isSeq(seq) ? seq : String.val(seq);
            return new BoolImpl(check(Z3.mk_seq_in_re(contextPtr, seqExpr.ast, re.ast)));
        }
        function Union(...res) {
            if (res.length === 0) {
                throw new Error('Union requires at least one argument');
            }
            if (res.length === 1) {
                return res[0];
            }
            return new ReImpl(check(Z3.mk_re_union(contextPtr, res.map(r => r.ast))));
        }
        function Intersect(...res) {
            if (res.length === 0) {
                throw new Error('Intersect requires at least one argument');
            }
            if (res.length === 1) {
                return res[0];
            }
            return new ReImpl(check(Z3.mk_re_intersect(contextPtr, res.map(r => r.ast))));
        }
        function ReConcat(...res) {
            if (res.length === 0) {
                throw new Error('ReConcat requires at least one argument');
            }
            if (res.length === 1) {
                return res[0];
            }
            return new ReImpl(check(Z3.mk_re_concat(contextPtr, res.map(r => r.ast))));
        }
        function Plus(re) {
            return new ReImpl(check(Z3.mk_re_plus(contextPtr, re.ast)));
        }
        function Star(re) {
            return new ReImpl(check(Z3.mk_re_star(contextPtr, re.ast)));
        }
        function Option(re) {
            return new ReImpl(check(Z3.mk_re_option(contextPtr, re.ast)));
        }
        function Complement(re) {
            return new ReImpl(check(Z3.mk_re_complement(contextPtr, re.ast)));
        }
        function Diff(a, b) {
            return new ReImpl(check(Z3.mk_re_diff(contextPtr, a.ast, b.ast)));
        }
        function Range(lo, hi) {
            const loSeq = isSeq(lo) ? lo : String.val(lo);
            const hiSeq = isSeq(hi) ? hi : String.val(hi);
            return new ReImpl(check(Z3.mk_re_range(contextPtr, loSeq.ast, hiSeq.ast)));
        }
        /**
         * Create a bounded repetition regex.
         * @param re The regex to repeat
         * @param lo Minimum number of repetitions
         * @param hi Maximum number of repetitions (0 means unbounded, i.e., at least lo)
         */
        function Loop(re, lo, hi = 0) {
            return new ReImpl(check(Z3.mk_re_loop(contextPtr, re.ast, lo, hi)));
        }
        function Power(re, n) {
            return new ReImpl(check(Z3.mk_re_power(contextPtr, re.ast, n)));
        }
        function AllChar(reSort) {
            return new ReImpl(check(Z3.mk_re_allchar(contextPtr, reSort.ptr)));
        }
        function Empty(reSort) {
            return new ReImpl(check(Z3.mk_re_empty(contextPtr, reSort.ptr)));
        }
        function Full(reSort) {
            return new ReImpl(check(Z3.mk_re_full(contextPtr, reSort.ptr)));
        }
        function mkPartialOrder(sort, index) {
            return new FuncDeclImpl(check(Z3.mk_partial_order(contextPtr, sort.ptr, index)));
        }
        function mkTransitiveClosure(f) {
            return new FuncDeclImpl(check(Z3.mk_transitive_closure(contextPtr, f.ptr)));
        }
        async function polynomialSubresultants(p, q, x) {
            const result = await Z3.polynomial_subresultants(contextPtr, p.ast, q.ast, x.ast);
            return new AstVectorImpl(check(result));
        }
        class AstImpl {
            constructor(ptr) {
                this.ptr = ptr;
                this.ctx = ctx;
                const myAst = this.ast;
                Z3.inc_ref(contextPtr, myAst);
                cleanup.register(this, () => Z3.dec_ref(contextPtr, myAst), this);
            }
            get ast() {
                return this.ptr;
            }
            id() {
                return Z3.get_ast_id(contextPtr, this.ast);
            }
            eqIdentity(other) {
                _assertContext(other);
                return check(Z3.is_eq_ast(contextPtr, this.ast, other.ast));
            }
            neqIdentity(other) {
                _assertContext(other);
                return !this.eqIdentity(other);
            }
            sexpr() {
                return Z3.ast_to_string(contextPtr, this.ast);
            }
            hash() {
                return Z3.get_ast_hash(contextPtr, this.ast);
            }
            toString() {
                return this.sexpr();
            }
        }
        class SolverImpl {
            get ptr() {
                _assertPtr(this._ptr);
                return this._ptr;
            }
            constructor(ptr = Z3.mk_solver(contextPtr)) {
                this.ctx = ctx;
                let myPtr;
                if (typeof ptr === 'string') {
                    myPtr = check(Z3.mk_solver_for_logic(contextPtr, _toSymbol(ptr)));
                }
                else {
                    myPtr = ptr;
                }
                this._ptr = myPtr;
                Z3.solver_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.solver_dec_ref(contextPtr, myPtr), this);
            }
            set(key, value) {
                Z3.solver_set_params(contextPtr, this.ptr, _toParams(key, value));
            }
            push() {
                Z3.solver_push(contextPtr, this.ptr);
            }
            pop(num = 1) {
                Z3.solver_pop(contextPtr, this.ptr, num);
            }
            numScopes() {
                return Z3.solver_get_num_scopes(contextPtr, this.ptr);
            }
            reset() {
                Z3.solver_reset(contextPtr, this.ptr);
            }
            add(...exprs) {
                _flattenArgs(exprs).forEach(expr => {
                    _assertContext(expr);
                    check(Z3.solver_assert(contextPtr, this.ptr, expr.ast));
                });
            }
            addAndTrack(expr, constant) {
                if (typeof constant === 'string') {
                    constant = Bool.const(constant);
                }
                (0, utils_1.assert)(isConst(constant), 'Provided expression that is not a constant to addAndTrack');
                check(Z3.solver_assert_and_track(contextPtr, this.ptr, expr.ast, constant.ast));
            }
            addSimplifier(simplifier) {
                _assertContext(simplifier);
                check(Z3.solver_add_simplifier(contextPtr, this.ptr, simplifier.ptr));
            }
            assertions() {
                return new AstVectorImpl(check(Z3.solver_get_assertions(contextPtr, this.ptr)));
            }
            async check(...exprs) {
                const assumptions = _flattenArgs(exprs).map(expr => {
                    _assertContext(expr);
                    return expr.ast;
                });
                const result = await asyncMutex.runExclusive(() => check(Z3.solver_check_assumptions(contextPtr, this.ptr, assumptions)));
                switch (result) {
                    case low_level_1.Z3_lbool.Z3_L_FALSE:
                        return 'unsat';
                    case low_level_1.Z3_lbool.Z3_L_TRUE:
                        return 'sat';
                    case low_level_1.Z3_lbool.Z3_L_UNDEF:
                        return 'unknown';
                    default:
                        (0, utils_1.assertExhaustive)(result);
                }
            }
            unsatCore() {
                return new AstVectorImpl(check(Z3.solver_get_unsat_core(contextPtr, this.ptr)));
            }
            model() {
                return new ModelImpl(check(Z3.solver_get_model(contextPtr, this.ptr)));
            }
            statistics() {
                return new StatisticsImpl(check(Z3.solver_get_statistics(contextPtr, this.ptr)));
            }
            reasonUnknown() {
                return check(Z3.solver_get_reason_unknown(contextPtr, this.ptr));
            }
            toString() {
                return check(Z3.solver_to_string(contextPtr, this.ptr));
            }
            toSmtlib2(status = 'unknown') {
                const assertionsVec = this.assertions();
                const numAssertions = assertionsVec.length();
                let formula;
                let assumptions;
                if (numAssertions > 0) {
                    // Use last assertion as formula and rest as assumptions
                    assumptions = [];
                    for (let i = 0; i < numAssertions - 1; i++) {
                        assumptions.push(assertionsVec.get(i).ast);
                    }
                    formula = assertionsVec.get(numAssertions - 1).ast;
                }
                else {
                    // No assertions, use true
                    assumptions = [];
                    formula = ctx.Bool.val(true).ast;
                }
                return check(Z3.benchmark_to_smtlib_string(contextPtr, '', '', status, '', assumptions, formula));
            }
            fromString(s) {
                Z3.solver_from_string(contextPtr, this.ptr, s);
                throwIfError();
            }
            units() {
                return new AstVectorImpl(check(Z3.solver_get_units(contextPtr, this.ptr)));
            }
            nonUnits() {
                return new AstVectorImpl(check(Z3.solver_get_non_units(contextPtr, this.ptr)));
            }
            trail() {
                return new AstVectorImpl(check(Z3.solver_get_trail(contextPtr, this.ptr)));
            }
            congruenceRoot(expr) {
                _assertContext(expr);
                return _toExpr(check(Z3.solver_congruence_root(contextPtr, this.ptr, expr.ast)));
            }
            congruenceNext(expr) {
                _assertContext(expr);
                return _toExpr(check(Z3.solver_congruence_next(contextPtr, this.ptr, expr.ast)));
            }
            congruenceExplain(a, b) {
                _assertContext(a);
                _assertContext(b);
                return _toExpr(check(Z3.solver_congruence_explain(contextPtr, this.ptr, a.ast, b.ast)));
            }
            fromFile(filename) {
                Z3.solver_from_file(contextPtr, this.ptr, filename);
                throwIfError();
            }
            release() {
                Z3.solver_dec_ref(contextPtr, this.ptr);
                // Mark the ptr as null to prevent double free
                this._ptr = null;
                cleanup.unregister(this);
            }
        }
        class OptimizeImpl {
            get ptr() {
                _assertPtr(this._ptr);
                return this._ptr;
            }
            constructor(ptr = Z3.mk_optimize(contextPtr)) {
                this.ctx = ctx;
                let myPtr;
                myPtr = ptr;
                this._ptr = myPtr;
                Z3.optimize_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.optimize_dec_ref(contextPtr, myPtr), this);
            }
            set(key, value) {
                Z3.optimize_set_params(contextPtr, this.ptr, _toParams(key, value));
            }
            push() {
                Z3.optimize_push(contextPtr, this.ptr);
            }
            pop() {
                Z3.optimize_pop(contextPtr, this.ptr);
            }
            add(...exprs) {
                _flattenArgs(exprs).forEach(expr => {
                    _assertContext(expr);
                    check(Z3.optimize_assert(contextPtr, this.ptr, expr.ast));
                });
            }
            addSoft(expr, weight, id = '') {
                if (isCoercibleRational(weight)) {
                    weight = `${weight.numerator}/${weight.denominator}`;
                }
                check(Z3.optimize_assert_soft(contextPtr, this.ptr, expr.ast, weight.toString(), _toSymbol(id)));
            }
            addAndTrack(expr, constant) {
                if (typeof constant === 'string') {
                    constant = Bool.const(constant);
                }
                (0, utils_1.assert)(isConst(constant), 'Provided expression that is not a constant to addAndTrack');
                check(Z3.optimize_assert_and_track(contextPtr, this.ptr, expr.ast, constant.ast));
            }
            assertions() {
                return new AstVectorImpl(check(Z3.optimize_get_assertions(contextPtr, this.ptr)));
            }
            maximize(expr) {
                check(Z3.optimize_maximize(contextPtr, this.ptr, expr.ast));
            }
            minimize(expr) {
                check(Z3.optimize_minimize(contextPtr, this.ptr, expr.ast));
            }
            async check(...exprs) {
                const assumptions = _flattenArgs(exprs).map(expr => {
                    _assertContext(expr);
                    return expr.ast;
                });
                const result = await asyncMutex.runExclusive(() => check(Z3.optimize_check(contextPtr, this.ptr, assumptions)));
                switch (result) {
                    case low_level_1.Z3_lbool.Z3_L_FALSE:
                        return 'unsat';
                    case low_level_1.Z3_lbool.Z3_L_TRUE:
                        return 'sat';
                    case low_level_1.Z3_lbool.Z3_L_UNDEF:
                        return 'unknown';
                    default:
                        (0, utils_1.assertExhaustive)(result);
                }
            }
            model() {
                return new ModelImpl(check(Z3.optimize_get_model(contextPtr, this.ptr)));
            }
            statistics() {
                return new StatisticsImpl(check(Z3.optimize_get_statistics(contextPtr, this.ptr)));
            }
            toString() {
                return check(Z3.optimize_to_string(contextPtr, this.ptr));
            }
            fromString(s) {
                Z3.optimize_from_string(contextPtr, this.ptr, s);
                throwIfError();
            }
            release() {
                Z3.optimize_dec_ref(contextPtr, this.ptr);
                this._ptr = null;
                cleanup.unregister(this);
            }
        }
        class FixedpointImpl {
            get ptr() {
                _assertPtr(this._ptr);
                return this._ptr;
            }
            constructor(ptr = Z3.mk_fixedpoint(contextPtr)) {
                this.ctx = ctx;
                let myPtr;
                myPtr = ptr;
                this._ptr = myPtr;
                Z3.fixedpoint_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.fixedpoint_dec_ref(contextPtr, myPtr), this);
            }
            set(key, value) {
                Z3.fixedpoint_set_params(contextPtr, this.ptr, _toParams(key, value));
            }
            help() {
                return check(Z3.fixedpoint_get_help(contextPtr, this.ptr));
            }
            add(...constraints) {
                constraints.forEach(constraint => {
                    _assertContext(constraint);
                    check(Z3.fixedpoint_assert(contextPtr, this.ptr, constraint.ast));
                });
            }
            registerRelation(pred) {
                _assertContext(pred);
                check(Z3.fixedpoint_register_relation(contextPtr, this.ptr, pred.ptr));
            }
            addRule(rule, name) {
                _assertContext(rule);
                const symbol = _toSymbol(name ?? '');
                check(Z3.fixedpoint_add_rule(contextPtr, this.ptr, rule.ast, symbol));
            }
            addFact(pred, ...args) {
                _assertContext(pred);
                check(Z3.fixedpoint_add_fact(contextPtr, this.ptr, pred.ptr, args));
            }
            updateRule(rule, name) {
                _assertContext(rule);
                const symbol = _toSymbol(name);
                check(Z3.fixedpoint_update_rule(contextPtr, this.ptr, rule.ast, symbol));
            }
            async query(query) {
                _assertContext(query);
                const result = await asyncMutex.runExclusive(() => check(Z3.fixedpoint_query(contextPtr, this.ptr, query.ast)));
                switch (result) {
                    case low_level_1.Z3_lbool.Z3_L_FALSE:
                        return 'unsat';
                    case low_level_1.Z3_lbool.Z3_L_TRUE:
                        return 'sat';
                    case low_level_1.Z3_lbool.Z3_L_UNDEF:
                        return 'unknown';
                    default:
                        (0, utils_1.assertExhaustive)(result);
                }
            }
            async queryRelations(...relations) {
                relations.forEach(rel => _assertContext(rel));
                const decls = relations.map(rel => rel.ptr);
                const result = await asyncMutex.runExclusive(() => check(Z3.fixedpoint_query_relations(contextPtr, this.ptr, decls)));
                switch (result) {
                    case low_level_1.Z3_lbool.Z3_L_FALSE:
                        return 'unsat';
                    case low_level_1.Z3_lbool.Z3_L_TRUE:
                        return 'sat';
                    case low_level_1.Z3_lbool.Z3_L_UNDEF:
                        return 'unknown';
                    default:
                        (0, utils_1.assertExhaustive)(result);
                }
            }
            getAnswer() {
                const ans = check(Z3.fixedpoint_get_answer(contextPtr, this.ptr));
                return ans ? _toExpr(ans) : null;
            }
            getReasonUnknown() {
                return check(Z3.fixedpoint_get_reason_unknown(contextPtr, this.ptr));
            }
            getNumLevels(pred) {
                _assertContext(pred);
                return check(Z3.fixedpoint_get_num_levels(contextPtr, this.ptr, pred.ptr));
            }
            getCoverDelta(level, pred) {
                _assertContext(pred);
                const res = check(Z3.fixedpoint_get_cover_delta(contextPtr, this.ptr, level, pred.ptr));
                return res ? _toExpr(res) : null;
            }
            addCover(level, pred, property) {
                _assertContext(pred);
                _assertContext(property);
                check(Z3.fixedpoint_add_cover(contextPtr, this.ptr, level, pred.ptr, property.ast));
            }
            getRules() {
                return new AstVectorImpl(check(Z3.fixedpoint_get_rules(contextPtr, this.ptr)));
            }
            getAssertions() {
                return new AstVectorImpl(check(Z3.fixedpoint_get_assertions(contextPtr, this.ptr)));
            }
            setPredicateRepresentation(pred, kinds) {
                _assertContext(pred);
                const symbols = kinds.map(kind => _toSymbol(kind));
                check(Z3.fixedpoint_set_predicate_representation(contextPtr, this.ptr, pred.ptr, symbols));
            }
            toString() {
                return check(Z3.fixedpoint_to_string(contextPtr, this.ptr, []));
            }
            fromString(s) {
                const av = check(Z3.fixedpoint_from_string(contextPtr, this.ptr, s));
                return new AstVectorImpl(av);
            }
            fromFile(file) {
                const av = check(Z3.fixedpoint_from_file(contextPtr, this.ptr, file));
                return new AstVectorImpl(av);
            }
            statistics() {
                return new StatisticsImpl(check(Z3.fixedpoint_get_statistics(contextPtr, this.ptr)));
            }
            release() {
                Z3.fixedpoint_dec_ref(contextPtr, this.ptr);
                this._ptr = null;
                cleanup.unregister(this);
            }
        }
        class ModelImpl {
            get ptr() {
                _assertPtr(this._ptr);
                return this._ptr;
            }
            constructor(ptr = Z3.mk_model(contextPtr)) {
                this.ctx = ctx;
                this._ptr = ptr;
                Z3.model_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.model_dec_ref(contextPtr, ptr), this);
            }
            length() {
                return Z3.model_get_num_consts(contextPtr, this.ptr) + Z3.model_get_num_funcs(contextPtr, this.ptr);
            }
            [Symbol.iterator]() {
                return this.values();
            }
            *entries() {
                const length = this.length();
                for (let i = 0; i < length; i++) {
                    yield [i, this.get(i)];
                }
            }
            *keys() {
                for (const [key] of this.entries()) {
                    yield key;
                }
            }
            *values() {
                for (const [, value] of this.entries()) {
                    yield value;
                }
            }
            decls() {
                return [...this.values()];
            }
            sexpr() {
                return check(Z3.model_to_string(contextPtr, this.ptr));
            }
            toString() {
                return this.sexpr();
            }
            eval(expr, modelCompletion = false) {
                _assertContext(expr);
                const r = check(Z3.model_eval(contextPtr, this.ptr, expr.ast, modelCompletion));
                if (r === null) {
                    throw new types_1.Z3Error('Failed to evaluate expression in the model');
                }
                return _toExpr(r);
            }
            get(i, to) {
                (0, utils_1.assert)(to === undefined || typeof i === 'number');
                if (typeof i === 'number') {
                    const length = this.length();
                    if (i >= length) {
                        throw new RangeError(`expected index ${i} to be less than length ${length}`);
                    }
                    if (to === undefined) {
                        const numConsts = check(Z3.model_get_num_consts(contextPtr, this.ptr));
                        if (i < numConsts) {
                            return new FuncDeclImpl(check(Z3.model_get_const_decl(contextPtr, this.ptr, i)));
                        }
                        else {
                            return new FuncDeclImpl(check(Z3.model_get_func_decl(contextPtr, this.ptr, i - numConsts)));
                        }
                    }
                    if (to < 0) {
                        to += length;
                    }
                    if (to >= length) {
                        throw new RangeError(`expected index ${to} to be less than length ${length}`);
                    }
                    const result = [];
                    for (let j = i; j < to; j++) {
                        result.push(this.get(j));
                    }
                    return result;
                }
                else if (isFuncDecl(i) || (isExpr(i) && isConst(i))) {
                    const result = this.getInterp(i);
                    (0, utils_1.assert)(result !== null);
                    return result;
                }
                else if (isSort(i)) {
                    return this.getUniverse(i);
                }
                (0, utils_1.assert)(false, 'Number, declaration or constant expected');
            }
            updateValue(decl, a) {
                _assertContext(decl);
                _assertContext(a);
                if (isExpr(decl)) {
                    decl = decl.decl();
                }
                if (isFuncDecl(decl) && decl.arity() !== 0 && isFuncInterp(a)) {
                    const funcInterp = this.addFuncInterp(decl, a.elseValue());
                    for (let i = 0; i < a.numEntries(); i++) {
                        const e = a.entry(i);
                        const n = e.numArgs();
                        const args = global.Array(n).map((_, i) => e.argValue(i));
                        funcInterp.addEntry(args, e.value());
                    }
                    return;
                }
                if (!isFuncDecl(decl) || decl.arity() !== 0) {
                    throw new types_1.Z3Error('Expecting 0-ary function or constant expression');
                }
                if (!isAst(a)) {
                    throw new types_1.Z3Error('Only func declarations can be assigned to func interpretations');
                }
                check(Z3.add_const_interp(contextPtr, this.ptr, decl.ptr, a.ast));
            }
            addFuncInterp(decl, defaultValue) {
                const fi = check(Z3.add_func_interp(contextPtr, this.ptr, decl.ptr, decl.range().cast(defaultValue).ptr));
                return new FuncInterpImpl(fi);
            }
            getInterp(expr) {
                (0, utils_1.assert)(isFuncDecl(expr) || isConst(expr), 'Declaration expected');
                if (isConst(expr)) {
                    (0, utils_1.assert)(isExpr(expr));
                    expr = expr.decl();
                }
                (0, utils_1.assert)(isFuncDecl(expr));
                if (expr.arity() === 0) {
                    const result = check(Z3.model_get_const_interp(contextPtr, this.ptr, expr.ptr));
                    if (result === null) {
                        return null;
                    }
                    return _toExpr(result);
                }
                else {
                    const interp = check(Z3.model_get_func_interp(contextPtr, this.ptr, expr.ptr));
                    if (interp === null) {
                        return null;
                    }
                    return new FuncInterpImpl(interp);
                }
            }
            getUniverse(sort) {
                _assertContext(sort);
                return new AstVectorImpl(check(Z3.model_get_sort_universe(contextPtr, this.ptr, sort.ptr)));
            }
            numSorts() {
                return check(Z3.model_get_num_sorts(contextPtr, this.ptr));
            }
            getSort(i) {
                return _toSort(check(Z3.model_get_sort(contextPtr, this.ptr, i)));
            }
            getSorts() {
                const n = this.numSorts();
                const result = [];
                for (let i = 0; i < n; i++) {
                    result.push(this.getSort(i));
                }
                return result;
            }
            sortUniverse(sort) {
                return this.getUniverse(sort);
            }
            release() {
                Z3.model_dec_ref(contextPtr, this.ptr);
                this._ptr = null;
                cleanup.unregister(this);
            }
        }
        class StatisticsImpl {
            get ptr() {
                _assertPtr(this._ptr);
                return this._ptr;
            }
            constructor(ptr) {
                this.ctx = ctx;
                this._ptr = ptr;
                Z3.stats_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.stats_dec_ref(contextPtr, ptr), this);
            }
            size() {
                return Z3.stats_size(contextPtr, this.ptr);
            }
            keys() {
                const result = [];
                const sz = this.size();
                for (let i = 0; i < sz; i++) {
                    result.push(Z3.stats_get_key(contextPtr, this.ptr, i));
                }
                return result;
            }
            get(key) {
                const sz = this.size();
                for (let i = 0; i < sz; i++) {
                    if (Z3.stats_get_key(contextPtr, this.ptr, i) === key) {
                        if (Z3.stats_is_uint(contextPtr, this.ptr, i)) {
                            return Z3.stats_get_uint_value(contextPtr, this.ptr, i);
                        }
                        else {
                            return Z3.stats_get_double_value(contextPtr, this.ptr, i);
                        }
                    }
                }
                throw new Error(`Statistics key not found: ${key}`);
            }
            entries() {
                const result = [];
                const sz = this.size();
                for (let i = 0; i < sz; i++) {
                    const key = Z3.stats_get_key(contextPtr, this.ptr, i);
                    const isUint = Z3.stats_is_uint(contextPtr, this.ptr, i);
                    const isDouble = Z3.stats_is_double(contextPtr, this.ptr, i);
                    const value = isUint
                        ? Z3.stats_get_uint_value(contextPtr, this.ptr, i)
                        : Z3.stats_get_double_value(contextPtr, this.ptr, i);
                    result.push({
                        __typename: 'StatisticsEntry',
                        key,
                        value,
                        isUint,
                        isDouble,
                    });
                }
                return result;
            }
            [Symbol.iterator]() {
                return this.entries()[Symbol.iterator]();
            }
            release() {
                Z3.stats_dec_ref(contextPtr, this.ptr);
                this._ptr = null;
                cleanup.unregister(this);
            }
        }
        class FuncEntryImpl {
            constructor(ptr) {
                this.ptr = ptr;
                this.ctx = ctx;
                Z3.func_entry_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.func_entry_dec_ref(contextPtr, ptr), this);
            }
            numArgs() {
                return check(Z3.func_entry_get_num_args(contextPtr, this.ptr));
            }
            argValue(i) {
                return _toExpr(check(Z3.func_entry_get_arg(contextPtr, this.ptr, i)));
            }
            value() {
                return _toExpr(check(Z3.func_entry_get_value(contextPtr, this.ptr)));
            }
        }
        class FuncInterpImpl {
            constructor(ptr) {
                this.ptr = ptr;
                this.ctx = ctx;
                Z3.func_interp_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.func_interp_dec_ref(contextPtr, ptr), this);
            }
            elseValue() {
                return _toExpr(check(Z3.func_interp_get_else(contextPtr, this.ptr)));
            }
            numEntries() {
                return check(Z3.func_interp_get_num_entries(contextPtr, this.ptr));
            }
            arity() {
                return check(Z3.func_interp_get_arity(contextPtr, this.ptr));
            }
            entry(i) {
                return new FuncEntryImpl(check(Z3.func_interp_get_entry(contextPtr, this.ptr, i)));
            }
            addEntry(args, value) {
                const argsVec = new AstVectorImpl();
                for (const arg of args) {
                    argsVec.push(arg);
                }
                _assertContext(argsVec);
                _assertContext(value);
                (0, utils_1.assert)(this.arity() === argsVec.length(), "Number of arguments in entry doesn't match function arity");
                check(Z3.func_interp_add_entry(contextPtr, this.ptr, argsVec.ptr, value.ptr));
            }
        }
        class SortImpl extends AstImpl {
            get ast() {
                return Z3.sort_to_ast(contextPtr, this.ptr);
            }
            kind() {
                return Z3.get_sort_kind(contextPtr, this.ptr);
            }
            subsort(other) {
                _assertContext(other);
                return false;
            }
            cast(expr) {
                _assertContext(expr);
                (0, utils_1.assert)(expr.sort.eqIdentity(expr.sort), 'Sort mismatch');
                return expr;
            }
            name() {
                return _fromSymbol(Z3.get_sort_name(contextPtr, this.ptr));
            }
            eqIdentity(other) {
                _assertContext(other);
                return check(Z3.is_eq_sort(contextPtr, this.ptr, other.ptr));
            }
            neqIdentity(other) {
                return !this.eqIdentity(other);
            }
        }
        class FuncDeclImpl extends AstImpl {
            get ast() {
                return Z3.func_decl_to_ast(contextPtr, this.ptr);
            }
            name() {
                return _fromSymbol(Z3.get_decl_name(contextPtr, this.ptr));
            }
            arity() {
                return Z3.get_arity(contextPtr, this.ptr);
            }
            domain(i) {
                (0, utils_1.assert)(i < this.arity(), 'Index out of bounds');
                return _toSort(Z3.get_domain(contextPtr, this.ptr, i));
            }
            range() {
                return _toSort(Z3.get_range(contextPtr, this.ptr));
            }
            kind() {
                return Z3.get_decl_kind(contextPtr, this.ptr);
            }
            params() {
                const n = Z3.get_decl_num_parameters(contextPtr, this.ptr);
                const result = [];
                for (let i = 0; i < n; i++) {
                    const kind = check(Z3.get_decl_parameter_kind(contextPtr, this.ptr, i));
                    switch (kind) {
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_INT:
                            result.push(check(Z3.get_decl_int_parameter(contextPtr, this.ptr, i)));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_DOUBLE:
                            result.push(check(Z3.get_decl_double_parameter(contextPtr, this.ptr, i)));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_RATIONAL:
                            result.push(check(Z3.get_decl_rational_parameter(contextPtr, this.ptr, i)));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_SYMBOL:
                            result.push(_fromSymbol(check(Z3.get_decl_symbol_parameter(contextPtr, this.ptr, i))));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_SORT:
                            result.push(new SortImpl(check(Z3.get_decl_sort_parameter(contextPtr, this.ptr, i))));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_AST:
                            result.push(new ExprImpl(check(Z3.get_decl_ast_parameter(contextPtr, this.ptr, i))));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_FUNC_DECL:
                            result.push(new FuncDeclImpl(check(Z3.get_decl_func_decl_parameter(contextPtr, this.ptr, i))));
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_INTERNAL:
                            break;
                        case low_level_1.Z3_parameter_kind.Z3_PARAMETER_ZSTRING:
                            break;
                        default:
                            (0, utils_1.assertExhaustive)(kind);
                    }
                }
                return result;
            }
            call(...args) {
                (0, utils_1.assert)(args.length === this.arity(), `Incorrect number of arguments to ${this}`);
                return _toExpr(check(Z3.mk_app(contextPtr, this.ptr, args.map((arg, i) => {
                    return this.domain(i).cast(arg).ast;
                }))));
            }
        }
        class ExprImpl extends AstImpl {
            get sort() {
                return _toSort(Z3.get_sort(contextPtr, this.ast));
            }
            eq(other) {
                return new BoolImpl(check(Z3.mk_eq(contextPtr, this.ast, from(other).ast)));
            }
            neq(other) {
                return new BoolImpl(check(Z3.mk_distinct(contextPtr, [this, other].map(expr => from(expr).ast))));
            }
            name() {
                return this.decl().name();
            }
            params() {
                return this.decl().params();
            }
            decl() {
                (0, utils_1.assert)(isApp(this), 'Z3 application expected');
                return new FuncDeclImpl(check(Z3.get_app_decl(contextPtr, check(Z3.to_app(contextPtr, this.ast)))));
            }
            numArgs() {
                (0, utils_1.assert)(isApp(this), 'Z3 applicaiton expected');
                return check(Z3.get_app_num_args(contextPtr, check(Z3.to_app(contextPtr, this.ast))));
            }
            arg(i) {
                (0, utils_1.assert)(isApp(this), 'Z3 applicaiton expected');
                (0, utils_1.assert)(i < this.numArgs(), `Invalid argument index - expected ${i} to be less than ${this.numArgs()}`);
                return _toExpr(check(Z3.get_app_arg(contextPtr, check(Z3.to_app(contextPtr, this.ast)), i)));
            }
            children() {
                const num_args = this.numArgs();
                if (isApp(this)) {
                    const result = [];
                    for (let i = 0; i < num_args; i++) {
                        result.push(this.arg(i));
                    }
                    return result;
                }
                return [];
            }
        }
        class PatternImpl {
            constructor(ptr) {
                this.ptr = ptr;
                this.ctx = ctx;
                // TODO: implement rest of Pattern
            }
        }
        class BoolSortImpl extends SortImpl {
            cast(other) {
                if (typeof other === 'boolean') {
                    other = Bool.val(other);
                }
                (0, utils_1.assert)(isExpr(other), 'true, false or Z3 Boolean expression expected.');
                (0, utils_1.assert)(this.eqIdentity(other.sort), 'Value cannot be converted into a Z3 Boolean value');
                return other;
            }
            subsort(other) {
                _assertContext(other.ctx);
                return other instanceof ArithSortImpl;
            }
        }
        class BoolImpl extends ExprImpl {
            not() {
                return Not(this);
            }
            and(other) {
                return And(this, other);
            }
            or(other) {
                return Or(this, other);
            }
            xor(other) {
                return Xor(this, other);
            }
            implies(other) {
                return Implies(this, other);
            }
            iff(other) {
                return Iff(this, other);
            }
        }
        class ProbeImpl {
            constructor(ptr) {
                this.ptr = ptr;
                this.ctx = ctx;
            }
            apply(goal) {
                _assertContext(goal);
                return Z3.probe_apply(contextPtr, this.ptr, goal.ptr);
            }
        }
        class GoalImpl {
            constructor(models = true, unsat_cores = false, proofs = false) {
                this.ctx = ctx;
                const myPtr = check(Z3.mk_goal(contextPtr, models, unsat_cores, proofs));
                this.ptr = myPtr;
                Z3.goal_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.goal_dec_ref(contextPtr, myPtr), this);
            }
            // Factory method for creating from existing Z3_goal pointer
            static fromPtr(goalPtr) {
                const goal = Object.create(GoalImpl.prototype);
                goal.ctx = ctx;
                goal.ptr = goalPtr;
                Z3.goal_inc_ref(contextPtr, goalPtr);
                cleanup.register(goal, () => Z3.goal_dec_ref(contextPtr, goalPtr), goal);
                return goal;
            }
            add(...constraints) {
                for (const constraint of constraints) {
                    const boolConstraint = isBool(constraint) ? constraint : Bool.val(constraint);
                    _assertContext(boolConstraint);
                    Z3.goal_assert(contextPtr, this.ptr, boolConstraint.ast);
                }
            }
            size() {
                return Z3.goal_size(contextPtr, this.ptr);
            }
            get(i) {
                (0, utils_1.assert)(i >= 0 && i < this.size(), 'Index out of bounds');
                const ast = check(Z3.goal_formula(contextPtr, this.ptr, i));
                return new BoolImpl(ast);
            }
            depth() {
                return Z3.goal_depth(contextPtr, this.ptr);
            }
            inconsistent() {
                return Z3.goal_inconsistent(contextPtr, this.ptr);
            }
            precision() {
                return Z3.goal_precision(contextPtr, this.ptr);
            }
            reset() {
                Z3.goal_reset(contextPtr, this.ptr);
            }
            numExprs() {
                return Z3.goal_num_exprs(contextPtr, this.ptr);
            }
            isDecidedSat() {
                return Z3.goal_is_decided_sat(contextPtr, this.ptr);
            }
            isDecidedUnsat() {
                return Z3.goal_is_decided_unsat(contextPtr, this.ptr);
            }
            convertModel(model) {
                _assertContext(model);
                const convertedModel = check(Z3.goal_convert_model(contextPtr, this.ptr, model.ptr));
                return new ModelImpl(convertedModel);
            }
            asExpr() {
                const sz = this.size();
                if (sz === 0) {
                    return Bool.val(true);
                }
                else if (sz === 1) {
                    return this.get(0);
                }
                else {
                    const constraints = [];
                    for (let i = 0; i < sz; i++) {
                        constraints.push(this.get(i));
                    }
                    return And(...constraints);
                }
            }
            toString() {
                return Z3.goal_to_string(contextPtr, this.ptr);
            }
            dimacs(includeNames = true) {
                return Z3.goal_to_dimacs_string(contextPtr, this.ptr, includeNames);
            }
        }
        class ApplyResultImpl {
            constructor(ptr) {
                this.ctx = ctx;
                this.ptr = ptr;
                Z3.apply_result_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.apply_result_dec_ref(contextPtr, ptr), this);
            }
            length() {
                return Z3.apply_result_get_num_subgoals(contextPtr, this.ptr);
            }
            getSubgoal(i) {
                (0, utils_1.assert)(i >= 0 && i < this.length(), 'Index out of bounds');
                const goalPtr = check(Z3.apply_result_get_subgoal(contextPtr, this.ptr, i));
                return GoalImpl.fromPtr(goalPtr);
            }
            toString() {
                return Z3.apply_result_to_string(contextPtr, this.ptr);
            }
        }
        // Add indexer support to ApplyResultImpl
        const applyResultHandler = {
            get(target, prop) {
                if (typeof prop === 'string') {
                    const index = parseInt(prop, 10);
                    if (!isNaN(index) && index >= 0 && index < target.length()) {
                        return target.getSubgoal(index);
                    }
                }
                return target[prop];
            },
        };
        class TacticImpl {
            constructor(tactic) {
                this.ctx = ctx;
                let myPtr;
                if (typeof tactic === 'string') {
                    myPtr = check(Z3.mk_tactic(contextPtr, tactic));
                }
                else {
                    myPtr = tactic;
                }
                this.ptr = myPtr;
                Z3.tactic_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.tactic_dec_ref(contextPtr, myPtr), this);
            }
            async apply(goal) {
                let goalToUse;
                if (isBool(goal)) {
                    // Convert Bool expression to Goal
                    goalToUse = new GoalImpl();
                    goalToUse.add(goal);
                }
                else {
                    goalToUse = goal;
                }
                _assertContext(goalToUse);
                const result = await Z3.tactic_apply(contextPtr, this.ptr, goalToUse.ptr);
                const applyResult = new ApplyResultImpl(check(result));
                // Wrap with Proxy to enable indexer access
                return new Proxy(applyResult, applyResultHandler);
            }
            solver() {
                const solverPtr = check(Z3.mk_solver_from_tactic(contextPtr, this.ptr));
                return new SolverImpl(solverPtr);
            }
            help() {
                return Z3.tactic_get_help(contextPtr, this.ptr);
            }
            paramDescrs() {
                const descrs = check(Z3.tactic_get_param_descrs(contextPtr, this.ptr));
                return new ParamDescrsImpl(descrs);
            }
            usingParams(params) {
                _assertContext(params);
                const newTactic = check(Z3.tactic_using_params(contextPtr, this.ptr, params.ptr));
                return new TacticImpl(newTactic);
            }
        }
        class ParamsImpl {
            constructor(params) {
                this.ctx = ctx;
                if (params) {
                    this.ptr = params;
                }
                else {
                    this.ptr = Z3.mk_params(contextPtr);
                }
                Z3.params_inc_ref(contextPtr, this.ptr);
                cleanup.register(this, () => Z3.params_dec_ref(contextPtr, this.ptr), this);
            }
            set(name, value) {
                const sym = _toSymbol(name);
                if (typeof value === 'boolean') {
                    Z3.params_set_bool(contextPtr, this.ptr, sym, value);
                }
                else if (typeof value === 'number') {
                    if (Number.isInteger(value)) {
                        check(Z3.params_set_uint(contextPtr, this.ptr, sym, value));
                    }
                    else {
                        check(Z3.params_set_double(contextPtr, this.ptr, sym, value));
                    }
                }
                else if (typeof value === 'string') {
                    check(Z3.params_set_symbol(contextPtr, this.ptr, sym, _toSymbol(value)));
                }
            }
            validate(descrs) {
                _assertContext(descrs);
                Z3.params_validate(contextPtr, this.ptr, descrs.ptr);
            }
            toString() {
                return Z3.params_to_string(contextPtr, this.ptr);
            }
        }
        class ParamDescrsImpl {
            constructor(paramDescrs) {
                this.ctx = ctx;
                this.ptr = paramDescrs;
                Z3.param_descrs_inc_ref(contextPtr, this.ptr);
                cleanup.register(this, () => Z3.param_descrs_dec_ref(contextPtr, this.ptr), this);
            }
            size() {
                return Z3.param_descrs_size(contextPtr, this.ptr);
            }
            getName(i) {
                const sym = Z3.param_descrs_get_name(contextPtr, this.ptr, i);
                const name = _fromSymbol(sym);
                return typeof name === 'string' ? name : `${name}`;
            }
            getKind(name) {
                return Z3.param_descrs_get_kind(contextPtr, this.ptr, _toSymbol(name));
            }
            getDocumentation(name) {
                return Z3.param_descrs_get_documentation(contextPtr, this.ptr, _toSymbol(name));
            }
            toString() {
                return Z3.param_descrs_to_string(contextPtr, this.ptr);
            }
        }
        class SimplifierImpl {
            constructor(simplifier) {
                this.ctx = ctx;
                let myPtr;
                if (typeof simplifier === 'string') {
                    myPtr = check(Z3.mk_simplifier(contextPtr, simplifier));
                }
                else {
                    myPtr = simplifier;
                }
                this.ptr = myPtr;
                Z3.simplifier_inc_ref(contextPtr, myPtr);
                cleanup.register(this, () => Z3.simplifier_dec_ref(contextPtr, myPtr), this);
            }
            help() {
                return Z3.simplifier_get_help(contextPtr, this.ptr);
            }
            paramDescrs() {
                const descrs = check(Z3.simplifier_get_param_descrs(contextPtr, this.ptr));
                return new ParamDescrsImpl(descrs);
            }
            usingParams(params) {
                _assertContext(params);
                const newSimplifier = check(Z3.simplifier_using_params(contextPtr, this.ptr, params.ptr));
                return new SimplifierImpl(newSimplifier);
            }
            andThen(other) {
                _assertContext(other);
                const newSimplifier = check(Z3.simplifier_and_then(contextPtr, this.ptr, other.ptr));
                return new SimplifierImpl(newSimplifier);
            }
        }
        class ArithSortImpl extends SortImpl {
            cast(other) {
                const sortTypeStr = isIntSort(this) ? 'IntSort' : 'RealSort';
                if (isExpr(other)) {
                    const otherS = other.sort;
                    if (isArith(other)) {
                        if (this.eqIdentity(otherS)) {
                            return other;
                        }
                        else if (isIntSort(otherS) && isRealSort(this)) {
                            return ToReal(other);
                        }
                        (0, utils_1.assert)(false, "Can't cast Real to IntSort without loss");
                    }
                    else if (isBool(other)) {
                        if (isIntSort(this)) {
                            return If(other, 1, 0);
                        }
                        else {
                            return ToReal(If(other, 1, 0));
                        }
                    }
                    (0, utils_1.assert)(false, `Can't cast expression to ${sortTypeStr}`);
                }
                else {
                    if (typeof other !== 'boolean') {
                        if (isIntSort(this)) {
                            (0, utils_1.assert)(!isCoercibleRational(other), "Can't cast fraction to IntSort");
                            return Int.val(other);
                        }
                        return Real.val(other);
                    }
                    (0, utils_1.assert)(false, `Can't cast primitive to ${sortTypeStr}`);
                }
            }
        }
        function Sum(arg0, ...args) {
            if (arg0 instanceof BitVecImpl) {
                // Assert only 2
                if (args.length !== 1) {
                    throw new Error('BitVec add only supports 2 arguments');
                }
                return new BitVecImpl(check(Z3.mk_bvadd(contextPtr, arg0.ast, arg0.sort.cast(args[0]).ast)));
            }
            else {
                (0, utils_1.assert)(arg0 instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_add(contextPtr, [arg0.ast].concat(args.map(arg => arg0.sort.cast(arg).ast)))));
            }
        }
        function Sub(arg0, ...args) {
            if (arg0 instanceof BitVecImpl) {
                // Assert only 2
                if (args.length !== 1) {
                    throw new Error('BitVec sub only supports 2 arguments');
                }
                return new BitVecImpl(check(Z3.mk_bvsub(contextPtr, arg0.ast, arg0.sort.cast(args[0]).ast)));
            }
            else {
                (0, utils_1.assert)(arg0 instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_sub(contextPtr, [arg0.ast].concat(args.map(arg => arg0.sort.cast(arg).ast)))));
            }
        }
        function Product(arg0, ...args) {
            if (arg0 instanceof BitVecImpl) {
                // Assert only 2
                if (args.length !== 1) {
                    throw new Error('BitVec mul only supports 2 arguments');
                }
                return new BitVecImpl(check(Z3.mk_bvmul(contextPtr, arg0.ast, arg0.sort.cast(args[0]).ast)));
            }
            else {
                (0, utils_1.assert)(arg0 instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_mul(contextPtr, [arg0.ast].concat(args.map(arg => arg0.sort.cast(arg).ast)))));
            }
        }
        function Div(arg0, arg1) {
            if (arg0 instanceof BitVecImpl) {
                return new BitVecImpl(check(Z3.mk_bvsdiv(contextPtr, arg0.ast, arg0.sort.cast(arg1).ast)));
            }
            else {
                (0, utils_1.assert)(arg0 instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_div(contextPtr, arg0.ast, arg0.sort.cast(arg1).ast)));
            }
        }
        function BUDiv(arg0, arg1) {
            return new BitVecImpl(check(Z3.mk_bvudiv(contextPtr, arg0.ast, arg0.sort.cast(arg1).ast)));
        }
        function Neg(a) {
            if (a instanceof BitVecImpl) {
                return new BitVecImpl(check(Z3.mk_bvneg(contextPtr, a.ast)));
            }
            else {
                (0, utils_1.assert)(a instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_unary_minus(contextPtr, a.ast)));
            }
        }
        function Mod(a, b) {
            if (a instanceof BitVecImpl) {
                return new BitVecImpl(check(Z3.mk_bvsrem(contextPtr, a.ast, a.sort.cast(b).ast)));
            }
            else {
                (0, utils_1.assert)(a instanceof ArithImpl);
                return new ArithImpl(check(Z3.mk_mod(contextPtr, a.ast, a.sort.cast(b).ast)));
            }
        }
        class ArithImpl extends ExprImpl {
            add(other) {
                return Sum(this, other);
            }
            mul(other) {
                return Product(this, other);
            }
            sub(other) {
                return Sub(this, other);
            }
            pow(exponent) {
                return new ArithImpl(check(Z3.mk_power(contextPtr, this.ast, this.sort.cast(exponent).ast)));
            }
            div(other) {
                return Div(this, other);
            }
            mod(other) {
                return Mod(this, other);
            }
            neg() {
                return Neg(this);
            }
            le(other) {
                return LE(this, other);
            }
            lt(other) {
                return LT(this, other);
            }
            gt(other) {
                return GT(this, other);
            }
            ge(other) {
                return GE(this, other);
            }
        }
        class IntNumImpl extends ArithImpl {
            value() {
                return BigInt(this.asString());
            }
            asString() {
                return Z3.get_numeral_string(contextPtr, this.ast);
            }
            asBinary() {
                return Z3.get_numeral_binary_string(contextPtr, this.ast);
            }
        }
        class RatNumImpl extends ArithImpl {
            value() {
                return { numerator: this.numerator().value(), denominator: this.denominator().value() };
            }
            numerator() {
                return new IntNumImpl(Z3.get_numerator(contextPtr, this.ast));
            }
            denominator() {
                return new IntNumImpl(Z3.get_denominator(contextPtr, this.ast));
            }
            asNumber() {
                const { numerator, denominator } = this.value();
                const div = numerator / denominator;
                return Number(div) + Number(numerator - div * denominator) / Number(denominator);
            }
            asDecimal(prec = Number.parseInt(getParam('precision') ?? FALLBACK_PRECISION.toString())) {
                return Z3.get_numeral_decimal_string(contextPtr, this.ast, prec);
            }
            asString() {
                return Z3.get_numeral_string(contextPtr, this.ast);
            }
        }
        class RCFNumImpl {
            constructor(valueOrPtr) {
                this.ctx = ctx;
                let myPtr;
                if (typeof valueOrPtr === 'string') {
                    myPtr = check(Z3.rcf_mk_rational(contextPtr, valueOrPtr));
                }
                else if (typeof valueOrPtr === 'number') {
                    myPtr = check(Z3.rcf_mk_small_int(contextPtr, valueOrPtr));
                }
                else {
                    myPtr = valueOrPtr;
                }
                this.ptr = myPtr;
                cleanup.register(this, () => Z3.rcf_del(contextPtr, myPtr), this);
            }
            add(other) {
                _assertContext(other);
                return new RCFNumImpl(check(Z3.rcf_add(contextPtr, this.ptr, other.ptr)));
            }
            sub(other) {
                _assertContext(other);
                return new RCFNumImpl(check(Z3.rcf_sub(contextPtr, this.ptr, other.ptr)));
            }
            mul(other) {
                _assertContext(other);
                return new RCFNumImpl(check(Z3.rcf_mul(contextPtr, this.ptr, other.ptr)));
            }
            div(other) {
                _assertContext(other);
                return new RCFNumImpl(check(Z3.rcf_div(contextPtr, this.ptr, other.ptr)));
            }
            neg() {
                return new RCFNumImpl(check(Z3.rcf_neg(contextPtr, this.ptr)));
            }
            inv() {
                return new RCFNumImpl(check(Z3.rcf_inv(contextPtr, this.ptr)));
            }
            power(k) {
                return new RCFNumImpl(check(Z3.rcf_power(contextPtr, this.ptr, k)));
            }
            lt(other) {
                _assertContext(other);
                return check(Z3.rcf_lt(contextPtr, this.ptr, other.ptr));
            }
            gt(other) {
                _assertContext(other);
                return check(Z3.rcf_gt(contextPtr, this.ptr, other.ptr));
            }
            le(other) {
                _assertContext(other);
                return check(Z3.rcf_le(contextPtr, this.ptr, other.ptr));
            }
            ge(other) {
                _assertContext(other);
                return check(Z3.rcf_ge(contextPtr, this.ptr, other.ptr));
            }
            eq(other) {
                _assertContext(other);
                return check(Z3.rcf_eq(contextPtr, this.ptr, other.ptr));
            }
            neq(other) {
                _assertContext(other);
                return check(Z3.rcf_neq(contextPtr, this.ptr, other.ptr));
            }
            isRational() {
                return check(Z3.rcf_is_rational(contextPtr, this.ptr));
            }
            isAlgebraic() {
                return check(Z3.rcf_is_algebraic(contextPtr, this.ptr));
            }
            isInfinitesimal() {
                return check(Z3.rcf_is_infinitesimal(contextPtr, this.ptr));
            }
            isTranscendental() {
                return check(Z3.rcf_is_transcendental(contextPtr, this.ptr));
            }
            toString(compact = false) {
                return check(Z3.rcf_num_to_string(contextPtr, this.ptr, compact, false));
            }
            toDecimal(precision) {
                return check(Z3.rcf_num_to_decimal_string(contextPtr, this.ptr, precision));
            }
        }
        class BitVecSortImpl extends SortImpl {
            size() {
                return Z3.get_bv_sort_size(contextPtr, this.ptr);
            }
            subsort(other) {
                return isBitVecSort(other) && this.size() < other.size();
            }
            cast(other) {
                if (isExpr(other)) {
                    _assertContext(other);
                    return other;
                }
                (0, utils_1.assert)(!isCoercibleRational(other), "Can't convert rational to BitVec");
                return BitVec.val(other, this.size());
            }
        }
        class BitVecImpl extends ExprImpl {
            size() {
                return this.sort.size();
            }
            add(other) {
                return Sum(this, other);
            }
            mul(other) {
                return Product(this, other);
            }
            sub(other) {
                return Sub(this, other);
            }
            sdiv(other) {
                return Div(this, other);
            }
            udiv(other) {
                return BUDiv(this, other);
            }
            smod(other) {
                return Mod(this, other);
            }
            urem(other) {
                return new BitVecImpl(check(Z3.mk_bvurem(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            srem(other) {
                return new BitVecImpl(check(Z3.mk_bvsrem(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            neg() {
                return Neg(this);
            }
            or(other) {
                return new BitVecImpl(check(Z3.mk_bvor(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            and(other) {
                return new BitVecImpl(check(Z3.mk_bvand(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            nand(other) {
                return new BitVecImpl(check(Z3.mk_bvnand(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            xor(other) {
                return new BitVecImpl(check(Z3.mk_bvxor(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            xnor(other) {
                return new BitVecImpl(check(Z3.mk_bvxnor(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            shr(count) {
                return new BitVecImpl(check(Z3.mk_bvashr(contextPtr, this.ast, this.sort.cast(count).ast)));
            }
            lshr(count) {
                return new BitVecImpl(check(Z3.mk_bvlshr(contextPtr, this.ast, this.sort.cast(count).ast)));
            }
            shl(count) {
                return new BitVecImpl(check(Z3.mk_bvshl(contextPtr, this.ast, this.sort.cast(count).ast)));
            }
            rotateRight(count) {
                return new BitVecImpl(check(Z3.mk_ext_rotate_right(contextPtr, this.ast, this.sort.cast(count).ast)));
            }
            rotateLeft(count) {
                return new BitVecImpl(check(Z3.mk_ext_rotate_left(contextPtr, this.ast, this.sort.cast(count).ast)));
            }
            not() {
                return new BitVecImpl(check(Z3.mk_bvnot(contextPtr, this.ast)));
            }
            extract(high, low) {
                return Extract(high, low, this);
            }
            signExt(count) {
                return new BitVecImpl(check(Z3.mk_sign_ext(contextPtr, count, this.ast)));
            }
            zeroExt(count) {
                return new BitVecImpl(check(Z3.mk_zero_ext(contextPtr, count, this.ast)));
            }
            repeat(count) {
                return new BitVecImpl(check(Z3.mk_repeat(contextPtr, count, this.ast)));
            }
            sle(other) {
                return SLE(this, other);
            }
            ule(other) {
                return ULE(this, other);
            }
            slt(other) {
                return SLT(this, other);
            }
            ult(other) {
                return ULT(this, other);
            }
            sge(other) {
                return SGE(this, other);
            }
            uge(other) {
                return UGE(this, other);
            }
            sgt(other) {
                return SGT(this, other);
            }
            ugt(other) {
                return UGT(this, other);
            }
            redAnd() {
                return new BitVecImpl(check(Z3.mk_bvredand(contextPtr, this.ast)));
            }
            redOr() {
                return new BitVecImpl(check(Z3.mk_bvredor(contextPtr, this.ast)));
            }
            addNoOverflow(other, isSigned) {
                return new BoolImpl(check(Z3.mk_bvadd_no_overflow(contextPtr, this.ast, this.sort.cast(other).ast, isSigned)));
            }
            addNoUnderflow(other) {
                return new BoolImpl(check(Z3.mk_bvadd_no_underflow(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            subNoOverflow(other) {
                return new BoolImpl(check(Z3.mk_bvsub_no_overflow(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            subNoUnderflow(other, isSigned) {
                return new BoolImpl(check(Z3.mk_bvsub_no_underflow(contextPtr, this.ast, this.sort.cast(other).ast, isSigned)));
            }
            sdivNoOverflow(other) {
                return new BoolImpl(check(Z3.mk_bvsdiv_no_overflow(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            mulNoOverflow(other, isSigned) {
                return new BoolImpl(check(Z3.mk_bvmul_no_overflow(contextPtr, this.ast, this.sort.cast(other).ast, isSigned)));
            }
            mulNoUnderflow(other) {
                return new BoolImpl(check(Z3.mk_bvmul_no_underflow(contextPtr, this.ast, this.sort.cast(other).ast)));
            }
            negNoOverflow() {
                return new BoolImpl(check(Z3.mk_bvneg_no_overflow(contextPtr, this.ast)));
            }
        }
        class BitVecNumImpl extends BitVecImpl {
            value() {
                return BigInt(this.asString());
            }
            asSignedValue() {
                let val = this.value();
                const size = BigInt(this.size());
                if (val >= 2n ** (size - 1n)) {
                    val = val - 2n ** size;
                }
                if (val < (-2n) ** (size - 1n)) {
                    val = val + 2n ** size;
                }
                return val;
            }
            asString() {
                return Z3.get_numeral_string(contextPtr, this.ast);
            }
            asBinaryString() {
                return Z3.get_numeral_binary_string(contextPtr, this.ast);
            }
        }
        class FPRMSortImpl extends SortImpl {
            cast(other) {
                if (isFPRM(other)) {
                    _assertContext(other);
                    return other;
                }
                throw new Error("Can't cast to FPRMSort");
            }
        }
        class FPRMImpl extends ExprImpl {
        }
        class FPSortImpl extends SortImpl {
            ebits() {
                return Z3.fpa_get_ebits(contextPtr, this.ptr);
            }
            sbits() {
                return Z3.fpa_get_sbits(contextPtr, this.ptr);
            }
            cast(other) {
                if (isExpr(other)) {
                    _assertContext(other);
                    return other;
                }
                if (typeof other === 'number') {
                    return Float.val(other, this);
                }
                throw new Error("Can't cast to FPSort");
            }
        }
        class FPImpl extends ExprImpl {
            add(rm, other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new FPImpl(check(Z3.mk_fpa_add(contextPtr, rm.ast, this.ast, otherFP.ast)));
            }
            sub(rm, other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new FPImpl(check(Z3.mk_fpa_sub(contextPtr, rm.ast, this.ast, otherFP.ast)));
            }
            mul(rm, other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new FPImpl(check(Z3.mk_fpa_mul(contextPtr, rm.ast, this.ast, otherFP.ast)));
            }
            div(rm, other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new FPImpl(check(Z3.mk_fpa_div(contextPtr, rm.ast, this.ast, otherFP.ast)));
            }
            neg() {
                return new FPImpl(check(Z3.mk_fpa_neg(contextPtr, this.ast)));
            }
            abs() {
                return new FPImpl(check(Z3.mk_fpa_abs(contextPtr, this.ast)));
            }
            sqrt(rm) {
                return new FPImpl(check(Z3.mk_fpa_sqrt(contextPtr, rm.ast, this.ast)));
            }
            rem(other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new FPImpl(check(Z3.mk_fpa_rem(contextPtr, this.ast, otherFP.ast)));
            }
            fma(rm, y, z) {
                const yFP = isFP(y) ? y : Float.val(y, this.sort);
                const zFP = isFP(z) ? z : Float.val(z, this.sort);
                return new FPImpl(check(Z3.mk_fpa_fma(contextPtr, rm.ast, this.ast, yFP.ast, zFP.ast)));
            }
            lt(other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new BoolImpl(check(Z3.mk_fpa_lt(contextPtr, this.ast, otherFP.ast)));
            }
            gt(other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new BoolImpl(check(Z3.mk_fpa_gt(contextPtr, this.ast, otherFP.ast)));
            }
            le(other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new BoolImpl(check(Z3.mk_fpa_leq(contextPtr, this.ast, otherFP.ast)));
            }
            ge(other) {
                const otherFP = isFP(other) ? other : Float.val(other, this.sort);
                return new BoolImpl(check(Z3.mk_fpa_geq(contextPtr, this.ast, otherFP.ast)));
            }
            isNaN() {
                return new BoolImpl(check(Z3.mk_fpa_is_nan(contextPtr, this.ast)));
            }
            isInf() {
                return new BoolImpl(check(Z3.mk_fpa_is_infinite(contextPtr, this.ast)));
            }
            isZero() {
                return new BoolImpl(check(Z3.mk_fpa_is_zero(contextPtr, this.ast)));
            }
            isNormal() {
                return new BoolImpl(check(Z3.mk_fpa_is_normal(contextPtr, this.ast)));
            }
            isSubnormal() {
                return new BoolImpl(check(Z3.mk_fpa_is_subnormal(contextPtr, this.ast)));
            }
            isNegative() {
                return new BoolImpl(check(Z3.mk_fpa_is_negative(contextPtr, this.ast)));
            }
            isPositive() {
                return new BoolImpl(check(Z3.mk_fpa_is_positive(contextPtr, this.ast)));
            }
        }
        class FPNumImpl extends FPImpl {
            value() {
                // Get the floating-point numeral as a JavaScript number
                // Note: This may lose precision for values outside JavaScript number range
                return Z3.get_numeral_double(contextPtr, this.ast);
            }
        }
        class SeqSortImpl extends SortImpl {
            isString() {
                return Z3.is_string_sort(contextPtr, this.ptr);
            }
            basis() {
                return _toSort(check(Z3.get_seq_sort_basis(contextPtr, this.ptr)));
            }
            cast(other) {
                if (isSeq(other)) {
                    _assertContext(other);
                    return other;
                }
                if (typeof other === 'string') {
                    return String.val(other);
                }
                throw new Error("Can't cast to SeqSort");
            }
        }
        class SeqImpl extends ExprImpl {
            isString() {
                return Z3.is_string_sort(contextPtr, Z3.get_sort(contextPtr, this.ast));
            }
            asString() {
                if (!Z3.is_string(contextPtr, this.ast)) {
                    throw new Error('Not a string value');
                }
                return Z3.get_string(contextPtr, this.ast);
            }
            concat(other) {
                const otherSeq = isSeq(other) ? other : String.val(other);
                return new SeqImpl(check(Z3.mk_seq_concat(contextPtr, [this.ast, otherSeq.ast])));
            }
            length() {
                return new ArithImpl(check(Z3.mk_seq_length(contextPtr, this.ast)));
            }
            at(index) {
                const indexExpr = isArith(index) ? index : Int.val(index);
                return new SeqImpl(check(Z3.mk_seq_at(contextPtr, this.ast, indexExpr.ast)));
            }
            nth(index) {
                const indexExpr = isArith(index) ? index : Int.val(index);
                return _toExpr(check(Z3.mk_seq_nth(contextPtr, this.ast, indexExpr.ast)));
            }
            extract(offset, length) {
                const offsetExpr = isArith(offset) ? offset : Int.val(offset);
                const lengthExpr = isArith(length) ? length : Int.val(length);
                return new SeqImpl(check(Z3.mk_seq_extract(contextPtr, this.ast, offsetExpr.ast, lengthExpr.ast)));
            }
            indexOf(substr, offset) {
                const substrSeq = isSeq(substr) ? substr : String.val(substr);
                const offsetExpr = offset !== undefined ? (isArith(offset) ? offset : Int.val(offset)) : Int.val(0);
                return new ArithImpl(check(Z3.mk_seq_index(contextPtr, this.ast, substrSeq.ast, offsetExpr.ast)));
            }
            lastIndexOf(substr) {
                const substrSeq = isSeq(substr) ? substr : String.val(substr);
                return new ArithImpl(check(Z3.mk_seq_last_index(contextPtr, this.ast, substrSeq.ast)));
            }
            contains(substr) {
                const substrSeq = isSeq(substr) ? substr : String.val(substr);
                return new BoolImpl(check(Z3.mk_seq_contains(contextPtr, this.ast, substrSeq.ast)));
            }
            prefixOf(s) {
                const sSeq = isSeq(s) ? s : String.val(s);
                return new BoolImpl(check(Z3.mk_seq_prefix(contextPtr, this.ast, sSeq.ast)));
            }
            suffixOf(s) {
                const sSeq = isSeq(s) ? s : String.val(s);
                return new BoolImpl(check(Z3.mk_seq_suffix(contextPtr, this.ast, sSeq.ast)));
            }
            replace(src, dst) {
                const srcSeq = isSeq(src) ? src : String.val(src);
                const dstSeq = isSeq(dst) ? dst : String.val(dst);
                return new SeqImpl(check(Z3.mk_seq_replace(contextPtr, this.ast, srcSeq.ast, dstSeq.ast)));
            }
            replaceAll(src, dst) {
                const srcSeq = isSeq(src) ? src : String.val(src);
                const dstSeq = isSeq(dst) ? dst : String.val(dst);
                return new SeqImpl(check(Z3.mk_seq_replace_all(contextPtr, this.ast, srcSeq.ast, dstSeq.ast)));
            }
        }
        class ReSortImpl extends SortImpl {
            basis() {
                return _toSort(check(Z3.get_re_sort_basis(contextPtr, this.ptr)));
            }
            cast(other) {
                if (isRe(other)) {
                    _assertContext(other);
                    return other;
                }
                throw new Error("Can't cast to ReSort");
            }
        }
        class ReImpl extends ExprImpl {
            plus() {
                return new ReImpl(check(Z3.mk_re_plus(contextPtr, this.ast)));
            }
            star() {
                return new ReImpl(check(Z3.mk_re_star(contextPtr, this.ast)));
            }
            option() {
                return new ReImpl(check(Z3.mk_re_option(contextPtr, this.ast)));
            }
            complement() {
                return new ReImpl(check(Z3.mk_re_complement(contextPtr, this.ast)));
            }
            union(other) {
                return new ReImpl(check(Z3.mk_re_union(contextPtr, [this.ast, other.ast])));
            }
            intersect(other) {
                return new ReImpl(check(Z3.mk_re_intersect(contextPtr, [this.ast, other.ast])));
            }
            diff(other) {
                return new ReImpl(check(Z3.mk_re_diff(contextPtr, this.ast, other.ast)));
            }
            concat(other) {
                return new ReImpl(check(Z3.mk_re_concat(contextPtr, [this.ast, other.ast])));
            }
            /**
             * Create a bounded repetition of this regex
             * @param lo Minimum number of repetitions
             * @param hi Maximum number of repetitions (0 means unbounded, i.e., at least lo)
             */
            loop(lo, hi = 0) {
                return new ReImpl(check(Z3.mk_re_loop(contextPtr, this.ast, lo, hi)));
            }
            power(n) {
                return new ReImpl(check(Z3.mk_re_power(contextPtr, this.ast, n)));
            }
        }
        class ArraySortImpl extends SortImpl {
            domain() {
                return _toSort(check(Z3.get_array_sort_domain(contextPtr, this.ptr)));
            }
            domain_n(i) {
                return _toSort(check(Z3.get_array_sort_domain_n(contextPtr, this.ptr, i)));
            }
            range() {
                return _toSort(check(Z3.get_array_sort_range(contextPtr, this.ptr)));
            }
        }
        class ArrayImpl extends ExprImpl {
            domain() {
                return this.sort.domain();
            }
            domain_n(i) {
                return this.sort.domain_n(i);
            }
            range() {
                return this.sort.range();
            }
            select(...indices) {
                return Select(this, ...indices);
            }
            store(...indicesAndValue) {
                return Store(this, ...indicesAndValue);
            }
            /**
             * Access the array default value.
             * Produces the default range value, for arrays that can be represented as
             * finite maps with a default range value.
             */
            default() {
                return _toExpr(check(Z3.mk_array_default(contextPtr, this.ast)));
            }
        }
        class SetImpl extends ExprImpl {
            elemSort() {
                return this.sort.domain();
            }
            union(...args) {
                return SetUnion(this, ...args);
            }
            intersect(...args) {
                return SetIntersect(this, ...args);
            }
            diff(b) {
                return SetDifference(this, b);
            }
            add(elem) {
                return SetAdd(this, elem);
            }
            del(elem) {
                return SetDel(this, elem);
            }
            complement() {
                return SetComplement(this);
            }
            contains(elem) {
                return isMember(elem, this);
            }
            subsetOf(b) {
                return isSubset(this, b);
            }
        }
        ////////////////////////////
        // Datatypes
        ////////////////////////////
        class DatatypeImpl {
            constructor(ctx, name) {
                this.constructors = [];
                this.ctx = ctx;
                this.name = name;
            }
            declare(name, ...fields) {
                this.constructors.push([name, fields]);
                return this;
            }
            create() {
                const datatypes = createDatatypes(this);
                return datatypes[0];
            }
        }
        class DatatypeSortImpl extends SortImpl {
            numConstructors() {
                return Z3.get_datatype_sort_num_constructors(contextPtr, this.ptr);
            }
            constructorDecl(idx) {
                const ptr = Z3.get_datatype_sort_constructor(contextPtr, this.ptr, idx);
                return new FuncDeclImpl(ptr);
            }
            recognizer(idx) {
                const ptr = Z3.get_datatype_sort_recognizer(contextPtr, this.ptr, idx);
                return new FuncDeclImpl(ptr);
            }
            accessor(constructorIdx, accessorIdx) {
                const ptr = Z3.get_datatype_sort_constructor_accessor(contextPtr, this.ptr, constructorIdx, accessorIdx);
                return new FuncDeclImpl(ptr);
            }
            cast(other) {
                if (isExpr(other)) {
                    (0, utils_1.assert)(this.eqIdentity(other.sort), 'Value cannot be converted to this datatype');
                    return other;
                }
                throw new Error('Cannot coerce value to datatype expression');
            }
            subsort(other) {
                _assertContext(other.ctx);
                return this.eqIdentity(other);
            }
        }
        class DatatypeExprImpl extends ExprImpl {
        }
        function createDatatypes(...datatypes) {
            if (datatypes.length === 0) {
                throw new Error('At least one datatype must be provided');
            }
            // All datatypes must be from the same context
            const dtCtx = datatypes[0].ctx;
            for (const dt of datatypes) {
                if (dt.ctx !== dtCtx) {
                    throw new Error('All datatypes must be from the same context');
                }
            }
            const sortNames = datatypes.map(dt => dt.name);
            const constructorLists = [];
            const scopedConstructors = [];
            try {
                // Create constructor lists for each datatype
                for (const dt of datatypes) {
                    const constructors = [];
                    for (const [constructorName, fields] of dt.constructors) {
                        const fieldNames = [];
                        const fieldSorts = [];
                        const fieldRefs = [];
                        for (const [fieldName, fieldSort] of fields) {
                            fieldNames.push(fieldName);
                            if (fieldSort instanceof DatatypeImpl) {
                                // Reference to another datatype being defined
                                const refIndex = datatypes.indexOf(fieldSort);
                                if (refIndex === -1) {
                                    throw new Error(`Referenced datatype "${fieldSort.name}" not found in datatypes being created`);
                                }
                                // For recursive references, we pass null and the ref index
                                fieldSorts.push(null); // null will be handled by the Z3 API
                                fieldRefs.push(refIndex);
                            }
                            else {
                                // Regular sort
                                fieldSorts.push(fieldSort.ptr);
                                fieldRefs.push(0);
                            }
                        }
                        const constructor = Z3.mk_constructor(contextPtr, Z3.mk_string_symbol(contextPtr, constructorName), Z3.mk_string_symbol(contextPtr, `is_${constructorName}`), fieldNames.map(name => Z3.mk_string_symbol(contextPtr, name)), fieldSorts, fieldRefs);
                        constructors.push(constructor);
                        scopedConstructors.push(constructor);
                    }
                    const constructorList = Z3.mk_constructor_list(contextPtr, constructors);
                    constructorLists.push(constructorList);
                }
                // Create the datatypes
                const sortSymbols = sortNames.map(name => Z3.mk_string_symbol(contextPtr, name));
                const resultSorts = Z3.mk_datatypes(contextPtr, sortSymbols, constructorLists);
                // Create DatatypeSortImpl instances
                const results = [];
                for (let i = 0; i < resultSorts.length; i++) {
                    const sortImpl = new DatatypeSortImpl(resultSorts[i]);
                    // Attach constructor, recognizer, and accessor functions dynamically
                    const numConstructors = sortImpl.numConstructors();
                    for (let j = 0; j < numConstructors; j++) {
                        const constructor = sortImpl.constructorDecl(j);
                        const recognizer = sortImpl.recognizer(j);
                        const constructorName = constructor.name().toString();
                        // Attach constructor function
                        if (constructor.arity() === 0) {
                            // Nullary constructor (constant)
                            sortImpl[constructorName] = constructor.call();
                        }
                        else {
                            sortImpl[constructorName] = constructor;
                        }
                        // Attach recognizer function
                        sortImpl[`is_${constructorName}`] = recognizer;
                        // Attach accessor functions
                        for (let k = 0; k < constructor.arity(); k++) {
                            const accessor = sortImpl.accessor(j, k);
                            const accessorName = accessor.name().toString();
                            sortImpl[accessorName] = accessor;
                        }
                    }
                    results.push(sortImpl);
                }
                return results;
            }
            finally {
                // Clean up resources
                for (const constructor of scopedConstructors) {
                    Z3.del_constructor(contextPtr, constructor);
                }
                for (const constructorList of constructorLists) {
                    Z3.del_constructor_list(contextPtr, constructorList);
                }
            }
        }
        class QuantifierImpl extends ExprImpl {
            is_forall() {
                return Z3.is_quantifier_forall(contextPtr, this.ast);
            }
            is_exists() {
                return Z3.is_quantifier_exists(contextPtr, this.ast);
            }
            is_lambda() {
                return Z3.is_lambda(contextPtr, this.ast);
            }
            weight() {
                return Z3.get_quantifier_weight(contextPtr, this.ast);
            }
            num_patterns() {
                return Z3.get_quantifier_num_patterns(contextPtr, this.ast);
            }
            pattern(i) {
                return new PatternImpl(check(Z3.get_quantifier_pattern_ast(contextPtr, this.ast, i)));
            }
            num_no_patterns() {
                return Z3.get_quantifier_num_no_patterns(contextPtr, this.ast);
            }
            no_pattern(i) {
                return _toExpr(check(Z3.get_quantifier_no_pattern_ast(contextPtr, this.ast, i)));
            }
            body() {
                return _toExpr(check(Z3.get_quantifier_body(contextPtr, this.ast)));
            }
            num_vars() {
                return Z3.get_quantifier_num_bound(contextPtr, this.ast);
            }
            var_name(i) {
                return _fromSymbol(Z3.get_quantifier_bound_name(contextPtr, this.ast, i));
            }
            var_sort(i) {
                return _toSort(check(Z3.get_quantifier_bound_sort(contextPtr, this.ast, i)));
            }
            children() {
                return [this.body()];
            }
        }
        class NonLambdaQuantifierImpl extends QuantifierImpl {
            not() {
                return Not(this);
            }
            and(other) {
                return And(this, other);
            }
            or(other) {
                return Or(this, other);
            }
            xor(other) {
                return Xor(this, other);
            }
            implies(other) {
                return Implies(this, other);
            }
            iff(other) {
                return Iff(this, other);
            }
        }
        // isBool will return false which is unlike the python API (but like the C API)
        class LambdaImpl extends QuantifierImpl {
            domain() {
                return this.sort.domain();
            }
            domain_n(i) {
                return this.sort.domain_n(i);
            }
            range() {
                return this.sort.range();
            }
            select(...indices) {
                return Select(this, ...indices);
            }
            store(...indicesAndValue) {
                return Store(this, ...indicesAndValue);
            }
            /**
             * Access the array default value.
             * Produces the default range value, for arrays that can be represented as
             * finite maps with a default range value.
             */
            default() {
                return _toExpr(check(Z3.mk_array_default(contextPtr, this.ast)));
            }
        }
        class AstVectorImpl {
            constructor(ptr = Z3.mk_ast_vector(contextPtr)) {
                this.ptr = ptr;
                this.ctx = ctx;
                Z3.ast_vector_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.ast_vector_dec_ref(contextPtr, ptr), this);
            }
            length() {
                return Z3.ast_vector_size(contextPtr, this.ptr);
            }
            [Symbol.iterator]() {
                return this.values();
            }
            *entries() {
                const length = this.length();
                for (let i = 0; i < length; i++) {
                    yield [i, this.get(i)];
                }
            }
            *keys() {
                for (let [key] of this.entries()) {
                    yield key;
                }
            }
            *values() {
                for (let [, value] of this.entries()) {
                    yield value;
                }
            }
            get(from, to) {
                const length = this.length();
                if (from < 0) {
                    from += length;
                }
                if (from >= length) {
                    throw new RangeError(`expected from index ${from} to be less than length ${length}`);
                }
                if (to === undefined) {
                    return _toAst(check(Z3.ast_vector_get(contextPtr, this.ptr, from)));
                }
                if (to < 0) {
                    to += length;
                }
                if (to >= length) {
                    throw new RangeError(`expected to index ${to} to be less than length ${length}`);
                }
                const result = [];
                for (let i = from; i < to; i++) {
                    result.push(_toAst(check(Z3.ast_vector_get(contextPtr, this.ptr, i))));
                }
                return result;
            }
            set(i, v) {
                _assertContext(v);
                if (i >= this.length()) {
                    throw new RangeError(`expected index ${i} to be less than length ${this.length()}`);
                }
                check(Z3.ast_vector_set(contextPtr, this.ptr, i, v.ast));
            }
            push(v) {
                _assertContext(v);
                check(Z3.ast_vector_push(contextPtr, this.ptr, v.ast));
            }
            resize(size) {
                check(Z3.ast_vector_resize(contextPtr, this.ptr, size));
            }
            has(v) {
                _assertContext(v);
                for (const item of this.values()) {
                    if (item.eqIdentity(v)) {
                        return true;
                    }
                }
                return false;
            }
            sexpr() {
                return check(Z3.ast_vector_to_string(contextPtr, this.ptr));
            }
        }
        class AstMapImpl {
            constructor(ptr = Z3.mk_ast_map(contextPtr)) {
                this.ptr = ptr;
                this.ctx = ctx;
                Z3.ast_map_inc_ref(contextPtr, ptr);
                cleanup.register(this, () => Z3.ast_map_dec_ref(contextPtr, ptr), this);
            }
            [Symbol.iterator]() {
                return this.entries();
            }
            get size() {
                return Z3.ast_map_size(contextPtr, this.ptr);
            }
            *entries() {
                for (const key of this.keys()) {
                    yield [key, this.get(key)];
                }
            }
            keys() {
                return new AstVectorImpl(Z3.ast_map_keys(contextPtr, this.ptr));
            }
            *values() {
                for (const [_, value] of this.entries()) {
                    yield value;
                }
            }
            get(key) {
                return _toAst(check(Z3.ast_map_find(contextPtr, this.ptr, key.ast)));
            }
            set(key, value) {
                check(Z3.ast_map_insert(contextPtr, this.ptr, key.ast, value.ast));
            }
            delete(key) {
                check(Z3.ast_map_erase(contextPtr, this.ptr, key.ast));
            }
            clear() {
                check(Z3.ast_map_reset(contextPtr, this.ptr));
            }
            has(key) {
                return check(Z3.ast_map_contains(contextPtr, this.ptr, key.ast));
            }
            sexpr() {
                return check(Z3.ast_map_to_string(contextPtr, this.ptr));
            }
        }
        function substitute(t, ...substitutions) {
            _assertContext(t);
            const from = [];
            const to = [];
            for (const [f, t] of substitutions) {
                _assertContext(f);
                _assertContext(t);
                from.push(f.ast);
                to.push(t.ast);
            }
            return _toExpr(check(Z3.substitute(contextPtr, t.ast, from, to)));
        }
        function substituteVars(t, ...to) {
            _assertContext(t);
            const toAsts = [];
            for (const expr of to) {
                _assertContext(expr);
                toAsts.push(expr.ast);
            }
            return _toExpr(check(Z3.substitute_vars(contextPtr, t.ast, toAsts)));
        }
        function substituteFuns(t, ...substitutions) {
            _assertContext(t);
            const from = [];
            const to = [];
            for (const [f, body] of substitutions) {
                _assertContext(f);
                _assertContext(body);
                from.push(f.ptr);
                to.push(body.ast);
            }
            return _toExpr(check(Z3.substitute_funs(contextPtr, t.ast, from, to)));
        }
        function updateField(t, fieldAccessor, newValue) {
            _assertContext(t);
            _assertContext(fieldAccessor);
            _assertContext(newValue);
            return _toExpr(check(Z3.datatype_update_field(contextPtr, fieldAccessor.ptr, t.ast, newValue.ast)));
        }
        function ast_from_string(s) {
            const sort_names = [];
            const sorts = [];
            const decl_names = [];
            const decls = [];
            const v = new AstVectorImpl(check(Z3.parse_smtlib2_string(contextPtr, s, sort_names, sorts, decl_names, decls)));
            if (v.length() !== 1) {
                throw new Error('Expected exactly one AST. Instead got ' + v.length() + ': ' + v.sexpr());
            }
            return v.get(0);
        }
        const ctx = {
            ptr: contextPtr,
            name,
            /////////////
            // Classes //
            /////////////
            Solver: SolverImpl,
            Optimize: OptimizeImpl,
            Fixedpoint: FixedpointImpl,
            Model: ModelImpl,
            Tactic: TacticImpl,
            Goal: GoalImpl,
            Params: ParamsImpl,
            Simplifier: SimplifierImpl,
            AstVector: AstVectorImpl,
            AstMap: AstMapImpl,
            ///////////////
            // Functions //
            ///////////////
            interrupt,
            setPrintMode,
            isModel,
            isAst,
            isSort,
            isFuncDecl,
            isFuncInterp,
            isApp,
            isConst,
            isExpr,
            isVar,
            isAppOf,
            isBool,
            isTrue,
            isFalse,
            isAnd,
            isOr,
            isImplies,
            isNot,
            isEq,
            isDistinct,
            isQuantifier,
            isArith,
            isArithSort,
            isInt,
            isIntVal,
            isIntSort,
            isReal,
            isRealVal,
            isRealSort,
            isRCFNum,
            isBitVecSort,
            isBitVec,
            isBitVecVal, // TODO fix ordering
            isFPRMSort,
            isFPRM,
            isFPSort,
            isFP,
            isFPVal,
            isSeqSort,
            isSeq,
            isStringSort,
            isString,
            isArraySort,
            isArray,
            isConstArray,
            isProbe,
            isTactic,
            isGoal,
            isAstVector,
            eqIdentity,
            getVarIndex,
            from,
            solve,
            /////////////
            // Objects //
            /////////////
            Sort,
            Function,
            RecFunc,
            Bool,
            Int,
            Real,
            RCFNum,
            BitVec,
            Float,
            FloatRM,
            String,
            Seq,
            Re,
            Array,
            Set,
            Datatype,
            ////////////////
            // Operations //
            ////////////////
            If,
            Distinct,
            Const,
            Consts,
            FreshConst,
            Var,
            Implies,
            Iff,
            Eq,
            Xor,
            Not,
            And,
            Or,
            PbEq,
            PbGe,
            PbLe,
            AtMost,
            AtLeast,
            ForAll,
            Exists,
            Lambda,
            ToReal,
            ToInt,
            IsInt,
            Sqrt,
            Cbrt,
            BV2Int,
            Int2BV,
            Concat,
            Cond,
            AndThen,
            OrElse,
            Repeat,
            TryFor,
            When,
            Skip,
            Fail,
            FailIf,
            ParOr,
            ParAndThen,
            With,
            LT,
            GT,
            LE,
            GE,
            ULT,
            UGT,
            ULE,
            UGE,
            SLT,
            SGT,
            SLE,
            SGE,
            Sum,
            Sub,
            Product,
            Div,
            BUDiv,
            Neg,
            Mod,
            Select,
            Store,
            Ext,
            Extract,
            substitute,
            substituteVars,
            substituteFuns,
            updateField,
            simplify,
            /////////////
            // Loading //
            /////////////
            ast_from_string,
            SetUnion,
            SetIntersect,
            SetDifference,
            SetAdd,
            SetDel,
            SetComplement,
            EmptySet,
            FullSet,
            isMember,
            isSubset,
            InRe,
            Union,
            Intersect,
            ReConcat,
            Plus,
            Star,
            Option,
            Complement,
            Diff,
            Range,
            Loop,
            Power,
            AllChar,
            Empty,
            Full,
            mkPartialOrder,
            mkTransitiveClosure,
            polynomialSubresultants,
        };
        cleanup.register(ctx, () => Z3.del_context(contextPtr));
        return ctx;
    }
    return {
        enableTrace,
        disableTrace,
        getVersion,
        getVersionString,
        getFullVersion,
        openLog,
        appendLog,
        getParam,
        setParam,
        resetParams,
        Context: createContext,
    };
}

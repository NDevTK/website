// query.js — pure query functions over a Trace
//
// Every function here is a simple read of precomputed trace
// arrays. No re-walking, no mutation. Safe to call arbitrarily.

'use strict';

function calls(trace, filter) {
  const out = [];
  for (const c of trace.calls) {
    if (filter && !matchCallFilter(c, filter)) continue;
    out.push(c);
  }
  return out;
}

function matchCallFilter(c, filter) {
  if (filter.targets && !filter.targets.some(t => (c.callee.text || '').startsWith(t))) return false;
  if (filter.reached && c.reachability !== 'reachable') return false;
  if (filter.site && !filter.site(c.site)) return false;
  return true;
}

function taintFlows(trace, filter) {
  const out = [];
  for (const f of trace.taintFlows) {
    if (filter && !matchFlowFilter(f, filter)) continue;
    out.push(f);
  }
  return out;
}

function matchFlowFilter(f, filter) {
  if (filter.severity && f.severity !== filter.severity) return false;
  if (filter.source && !f.source || (filter.source && f.source.label !== filter.source)) return false;
  if (filter.sinkKind && f.sink.kind !== filter.sinkKind) return false;
  return true;
}

function innerHtmlAssignments(trace) {
  return trace.innerHtmlAssignments.slice();
}

function stringLiterals(trace, filter) {
  const out = [];
  for (const l of trace.stringLiterals) {
    if (filter && filter.context && l.context !== filter.context) continue;
    out.push(l);
  }
  return out;
}

function valueSetOf(trace, path) {
  return trace.mayBe[path] || null;
}

function callGraph(trace) {
  return { nodes: trace.callGraph.nodes.slice(), edges: trace.callGraph.edges.slice() };
}

function assumptions(trace, filter) {
  const out = [];
  for (const a of trace.assumptions) {
    if (filter && !matchAssumptionFilter(a, filter)) continue;
    out.push(a);
  }
  return out;
}

function matchAssumptionFilter(a, filter) {
  if (filter.reason) {
    const reasons = Array.isArray(filter.reason) ? filter.reason : [filter.reason];
    if (!reasons.includes(a.reason)) return false;
  }
  if (filter.severity && a.severity !== filter.severity) return false;
  if (filter.file && a.location.file !== filter.file) return false;
  if (filter.affectsPath && a.affects !== filter.affectsPath) return false;
  return true;
}

function reachability(trace, location) {
  // Location may be passed by pos or by (file, line, col).
  if (typeof location === 'number') {
    for (const [loc, verdict] of trace.reachability) {
      if (loc.pos === location) return verdict;
    }
    return 'unknown';
  }
  for (const [loc, verdict] of trace.reachability) {
    if (loc.file === location.file && loc.line === location.line && loc.col === location.col) {
      return verdict;
    }
  }
  return 'unknown';
}

// Helper: accept a Value and return the single concrete primitive
// if it's a Concrete value, else null.
function asConcrete(value) {
  if (!value) return null;
  if (value.kind === 'concrete') return value.value;
  return null;
}

// Helper: enumerate every concrete primitive a Value can take, or
// null if it's unenumerable.
function enumerate(value) {
  if (!value) return null;
  if (value.kind === 'concrete') return [value.value];
  if (value.kind === 'oneOf') return value.values.slice();
  return null;
}

// Helper: resolve the flow-sensitively attached TypeDB typeName on
// the Value, or null.
function typeName(value) {
  return value && value.typeName ? value.typeName : null;
}

module.exports = {
  calls, taintFlows, innerHtmlAssignments, stringLiterals,
  valueSetOf, callGraph, assumptions, reachability,
  asConcrete, enumerate, typeName,
};

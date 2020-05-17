
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph


class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
        exists(MacroInvocation mi | mi.getExpr() = this and mi.getMacro().getName().regexpMatch("ntoh.*"))
    }
}

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
      exists(NetworkByteSwap nbs | source.asExpr() = nbs)
  }
  override predicate isSink(DataFlow::Node sink) {
    exists(FunctionCall fc | fc.getTarget().getName() = "memcpy" 
    and fc.getArgument(2) = sink.asExpr()
    )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
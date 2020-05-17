import cpp

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {

        exists(MacroInvocation mi | mi.getExpr() = this and mi.getMacro().getName().regexpMatch("ntoh.*"))


    }
}

from NetworkByteSwap nbs
select nbs

package com.rampage.flowdroid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JReturnStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.*;

public class InterProcedureAnalysis {
    protected static Logger logger = LoggerFactory.getLogger(InterProcedureAnalysis.class.getClass());

    public static List<Unit> findDefs(Body body, Stmt stmt, Local local) {
        HashSet<SootMethod> handledMethods = new HashSet<>();
        handledMethods.add(body.getMethod());
        CallGraph cg = Scene.v().getCallGraph();
        List<Unit> defs = new ArrayList<>();
        List<Unit> intraDefs = IntraProcedureAnalysis.findDefs(body, stmt, local);
        Iterator<Unit> iterator = intraDefs.iterator();
        while (iterator.hasNext()) {
            Unit intraDef = iterator.next();
            defs.add(intraDef);
            if (intraDef instanceof IdentityStmt) {
                Value identityRop = ((IdentityStmt) intraDef).getRightOp();
                if (!(identityRop instanceof ParameterRef)) {
                    logger.info("CASE-1: Right operator of IdentityStmt is not a ParameterRef instance.");
                    logger.info("{" + intraDef + "}");
                }else {
                    int index = ((ParameterRef) identityRop).getIndex();
                    Iterator<Edge> iteratorEdges = cg.edgesInto(body.getMethod());
                    while (iteratorEdges.hasNext()) {
                        Edge edge = iteratorEdges.next();
                        SootMethod srcMethod = edge.src();
                        if (handledMethods.contains(srcMethod)) {
                            logger.info("CASE-1: Recursive invocation happens.");
                            logger.info("{" + srcMethod.getSignature() + "} will call itself.");
                        }else {
                            handledMethods.add(srcMethod);
                            Body srcBody = srcMethod.retrieveActiveBody();
                            Stmt srcStmt = edge.srcStmt();
                            if (srcStmt.containsInvokeExpr()) {
                                Value srcArg = srcStmt.getInvokeExpr().getArg(index);
                                if (srcArg instanceof Local) {
                                    InterProcedureAnalysis.findDefsUtil(srcBody, srcStmt, (Local) srcArg, cg, handledMethods, defs);
                                }else if(srcArg instanceof Constant){
                                    defs.add(Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", srcArg.getType()), srcArg));
                                }else {
                                    logger.info("CASE-1: Argument of the invocation is not a constant value or a local variable.");
                                    logger.info("{" + srcStmt + "}");
                                }
                            } else {
                                logger.error("Assertion Error");
                            }
                        }
                    }
                    throw new AssertionError();
                }
            }
            if (intraDef instanceof AssignStmt && ((AssignStmt) intraDef).containsInvokeExpr()) {
                SootMethod tgtMethod = ((AssignStmt) intraDef).getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-2: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                }else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    BriefUnitGraph briefUnitGraph = new BriefUnitGraph(tgtBody);
                    Iterator<Unit> tails = briefUnitGraph.getTails().iterator();
                    while (tails.hasNext()) {
                        Unit tail = tails.next();
                        if (tail instanceof ReturnStmt) {
                            ReturnStmt tgtStmt = (ReturnStmt) tail;
                            Value tgtValue = tgtStmt.getOp();
                            if (tgtValue instanceof Local) {
                                InterProcedureAnalysis.findDefsUtil(tgtBody, tgtStmt, (Local) tgtValue, cg, handledMethods, defs);
                            }else if(tgtValue instanceof Constant){
                                defs.add(Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", tgtValue.getType()), tgtValue));
                            }else {
                                logger.info("CASE-2: The returned is not a constant value or a local variable.");
                                logger.info("{" + tgtStmt + "}");
                            }
                        }
                    }
                }
            }
        }
    return defs;
    }

    private static void findDefsUtil(Body body, Stmt stmt, Local local, CallGraph cg, HashSet<SootMethod> handledMethods, List<Unit> defs) {
        List<Unit> intraDefs = IntraProcedureAnalysis.findDefs(body, stmt, local);
        Iterator<Unit> iterator = intraDefs.iterator();
        while (iterator.hasNext()) {
            Unit intraDef = iterator.next();
            defs.add(intraDef);
            if (intraDef instanceof IdentityStmt) {
                Value identityRop = ((IdentityStmt) intraDef).getRightOp();
                if (!(identityRop instanceof ParameterRef)) {
                    logger.info("CASE-1: Right operator of IdentityStmt is not a ParameterRef instance.");
                    logger.info("{" + intraDef + "}");
                }else {
                    int index = ((ParameterRef) identityRop).getIndex();
                    Iterator<Edge> edges = cg.edgesInto(body.getMethod());
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod srcMethod = edge.src();
                        if (handledMethods.contains(srcMethod)) {
                            logger.info("CASE-1: Recursive invocation happens.");
                            logger.info("{" + srcMethod.getSignature() + "} will be called recursively.");
                        }else {
                            handledMethods.add(srcMethod);
                            Body srcBody = srcMethod.retrieveActiveBody();
                            Stmt srcStmt = edge.srcStmt();
                            if (srcStmt.containsInvokeExpr()) {
                               Value srcArg = srcStmt.getInvokeExpr().getArg(index);
                                if (srcArg instanceof Local) {
                                    InterProcedureAnalysis.findDefsUtil(srcBody, srcStmt, (Local) srcArg, cg, handledMethods, defs);
                                }else if(srcArg instanceof Constant){
                                    defs.add(Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", srcArg.getType()), srcArg));
                                }else {
                                    logger.info("CASE-1: Argument of the invocation is not a constant value or a local variable.");
                                    logger.info("{" + srcStmt + "}");
                                }
                            } else {
                                logger.error("Assertion Error");
                            }
                        }
                    }
                }
            }
            if (intraDef instanceof AssignStmt && ((AssignStmt) intraDef).containsInvokeExpr()) {
                SootMethod tgtMethod = ((AssignStmt) intraDef).getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-2: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will be called recursively.");
                }else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    BriefUnitGraph briefUnitGraph = new BriefUnitGraph(tgtBody);
                    Iterator<Unit> tails = briefUnitGraph.getTails().iterator();
                    while (tails.hasNext()) {
                        Unit tail = tails.next();
                        if (tail instanceof ReturnStmt) {
                            ReturnStmt tgtStmt = (ReturnStmt) tail;
                            Value tgtValue = tgtStmt.getOp();
                            if (tgtValue instanceof Local) {
                                InterProcedureAnalysis.findDefsUtil(tgtBody, tgtStmt, (Local) tgtValue, cg, handledMethods, defs);
                            }else if(tgtValue instanceof Constant){
                                defs.add(Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", tgtValue.getType()), tgtValue));
                            }else {
                                logger.info("CASE-2: The returned is not a constant value or a local variable.");
                                logger.info("{" + tgtStmt + "}");
                            }
                        }
                    }
                }
            }
        }
    }

    public static List<UnitValueBoxPair> findUses(Body body, Stmt stmt, Local local) {
        HashSet<SootMethod> handledMethods = new HashSet<>();
        handledMethods.add(body.getMethod());
        CallGraph cg = Scene.v().getCallGraph();
        List<UnitValueBoxPair> uses = new ArrayList<>();
        List<Unit> intraDefs = IntraProcedureAnalysis.findDefs(body, stmt, local);
        Iterator<Unit> iterator = intraDefs.iterator();
        while (iterator.hasNext()) {
            Unit intraDef = iterator.next();
            if (intraDef instanceof IdentityStmt) {
                Value identityRop = ((IdentityStmt) intraDef).getRightOp();
                if (!(identityRop instanceof ParameterRef)) {
                    logger.info("CASE-1: Right operator of IdentityStmt is not a ParameterRef instance.");
                    logger.info("{" + intraDef + "}");
                }else {
                    int index = ((ParameterRef) identityRop).getIndex();
                    Iterator<Edge> edges = cg.edgesInto(body.getMethod());
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod srcMethod = edge.src();
                        if (handledMethods.contains(srcMethod)) {
                            logger.info("CASE-1: Recursive invocation happens.");
                            logger.info("{" + srcMethod.getSignature() + "} will call itself.");
                        }else {
                            handledMethods.add(srcMethod);
                            Body srcBody = srcMethod.retrieveActiveBody();
                            Stmt srcStmt = edge.srcStmt();
                            Value srcArg = srcStmt.getInvokeExpr().getArg(index);
                            if (srcArg instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(srcBody, srcStmt, (Local) srcArg, cg, handledMethods, uses);
                            }else if(srcArg instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", srcArg.getType()), srcArg);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-1: Argument of the invocation is not a constant value or a local variable.");
                                logger.info("{" + srcStmt + "}");
                            }
                        }
                    }
                }
            }
            if (intraDef instanceof AssignStmt && ((AssignStmt) intraDef).containsInvokeExpr()) {
                SootMethod tgtMethod = ((AssignStmt) intraDef).getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-2: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                }else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    BriefUnitGraph briefUnitGraph = new BriefUnitGraph(tgtBody);
                    Iterator<Unit> tails = briefUnitGraph.getTails().iterator();
                    while (tails.hasNext()) {
                        Unit tail = tails.next();
                        if (tail instanceof ReturnStmt) {
                            ReturnStmt tgtStmt = (ReturnStmt) tail;
                            Value tgtValue = tgtStmt.getOp();
                            if (tgtValue instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(tgtBody, tgtStmt, (Local) tgtValue, cg, handledMethods, uses);
                            }else if(tgtValue instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", tgtValue.getType()), tgtValue);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-2: The returned is not a constant value or a local variable.");
                                logger.info("{" + tgtStmt + "}");
                            }
                        }
                    }
                }
            }
        }

        Iterator<UnitValueBoxPair> pairs = IntraProcedureAnalysis.findUses(body, stmt, local, false).iterator();
        while (pairs.hasNext()) {
            UnitValueBoxPair pair = pairs.next();
            Stmt intraUse = (Stmt) pair.unit;
            uses.add(pair);
            if (intraUse.containsInvokeExpr()) {
                if (!(intraUse instanceof AssignStmt) || pair.getValueBox() != ((AssignStmt) intraUse).getLeftOpBox()) {
                    SootMethod tgtMethod = intraUse.getInvokeExpr().getMethod();
                    if (handledMethods.contains(tgtMethod)) {
                        logger.info("CASE-3: Recursive invocation happens.");
                        logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                    }else if(tgtMethod.isConcrete()){
                        handledMethods.add(tgtMethod);
                        int argIndex = -1;
                        for (int index=0; index < intraUse.getInvokeExpr().getArgCount(); index++) {
                            if (pair.getValueBox() == intraUse.getInvokeExpr().getArgBox(index)) {
                                argIndex = index;
                            }
                        }
                        Body tgtBody = tgtMethod.retrieveActiveBody();
                        Stmt tgtStmt = null;
                        Local tgtLocal = null;
                        Iterator<Unit> units = tgtBody.getUnits().iterator();
                        while (units.hasNext()) {
                            Unit unit = units.next();
                            if (argIndex == -1) {
                                if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ThisRef) {
                                    tgtStmt = (Stmt) unit;
                                    tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                                }
                            }else if(unit instanceof IdentityStmt && (((IdentityStmt) unit).getRightOp() instanceof ParameterRef && ((ParameterRef)((IdentityStmt) unit).getRightOp()).getIndex() == argIndex)){
                                tgtStmt = (Stmt) unit;
                                tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                            }
                            if (tgtStmt == null) {
                                if (tgtLocal != null) {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                        if (tgtStmt != null && tgtLocal != null) {
                            InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, true);
                        }
                    }
                }
            }
            if (intraUse instanceof JReturnStmt) {
                logger.info("return unit");
            }
        }
        return uses;
    }

    public static List<UnitValueBoxPair> findUsesBackward(Body body, Stmt stmt, Local local) {
        HashSet<SootMethod> handledMethods = new HashSet<>();
        handledMethods.add(body.getMethod());
        CallGraph cg = Scene.v().getCallGraph();
        List<UnitValueBoxPair> uses = new ArrayList<>();
        Iterator<Unit> intraDefs = IntraProcedureAnalysis.findDefs(body, stmt, local).iterator();
        while (intraDefs.hasNext()) {
            Unit intraDef = intraDefs.next();
            if (intraDef instanceof IdentityStmt) {
                Value identityRop = ((IdentityStmt) intraDef).getRightOp();
                if (!(identityRop instanceof ParameterRef)) {
                    logger.info("CASE-1: Right operator of IdentityStmt is not a ParameterRef instance.");
                    logger.info("{" + intraDef + "}");
                }else {
                    int index = ((ParameterRef) identityRop).getIndex();
                    Iterator<Edge> edges = cg.edgesInto(body.getMethod());
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod srcMethod = edge.src();
                        if (handledMethods.contains(srcMethod)) {
                            logger.info("CASE-1: Recursive invocation happens.");
                            logger.info("{" + srcMethod.getSignature() + "} will call itself.");
                        }else {
                            handledMethods.add(srcMethod);
                            Body srcBody = srcMethod.retrieveActiveBody();
                            Stmt srcStmt = edge.srcStmt();
                            Value srcArg = srcStmt.getInvokeExpr().getArg(index);
                            if (srcArg instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(srcBody, srcStmt, (Local) srcArg, cg, handledMethods, uses);
                            }else if(srcArg instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", srcArg.getType()), srcArg);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-1: Argument of the invocation is not a constant value or a local variable.");
                                logger.info("{" + srcStmt + "}");
                            }
                        }
                    }
                }
            }
            if (intraDef instanceof AssignStmt && ((AssignStmt) intraDef).containsInvokeExpr()) {
                SootMethod tgtMethod = ((AssignStmt) intraDef).getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-2: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                } else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    BriefUnitGraph briefUnitGraph = new BriefUnitGraph(tgtBody);
                    Iterator<Unit> tails = briefUnitGraph.getTails().iterator();
                    while (tails.hasNext()) {
                        Unit tail = tails.next();
                        if (tail instanceof ReturnStmt) {
                            ReturnStmt tgtStmt = (ReturnStmt) tail;
                            Value tgtValue = tgtStmt.getOp();
                            if (tgtValue instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(tgtBody, tgtStmt, (Local) tgtValue, cg, handledMethods, uses);
                            }else if(tgtValue instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", tgtValue.getType()), tgtValue);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-2: The returned is not a constant value or a local variable.");
                                logger.info("{" + tgtStmt + "}");
                            }
                        }
                    }
                }
            }
        }
        Iterator<UnitValueBoxPair> pairs = IntraProcedureAnalysis.findUsesBackward(body, stmt, local, false).iterator();
        while (pairs.hasNext()) {
            UnitValueBoxPair pair = pairs.next();
            Stmt intraUse = (Stmt) pair.unit;
            uses.add(pair);
            if (intraUse.containsInvokeExpr() && (!(intraUse instanceof AssignStmt) || pair.getValueBox() != ((AssignStmt)intraUse).getLeftOpBox())) {
                SootMethod tgtMethod = intraUse.getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-3: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                }else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    int argIndex = -1;
                    for (int index = 0; index < intraUse.getInvokeExpr().getArgCount(); index++) {
                        if (pair.getValueBox() == intraUse.getInvokeExpr().getArgBox(index)) {
                            argIndex = index;
                        }
                    }
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    Stmt tgtStmt = null;
                    Local tgtLocal = null;
                    Iterator<Unit> units = tgtBody.getUnits().iterator();
                    while (units.hasNext()) {
                        Unit unit = units.next();
                        if (argIndex == -1) {
                            if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ThisRef) {
                                tgtStmt = (Stmt) unit;
                                tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                            }
                        }else if(unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ParameterRef && ((ParameterRef) ((IdentityStmt)unit).getRightOp()).getIndex() == argIndex){
                            tgtStmt = (Stmt) unit;
                            tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                        }
                        if (tgtStmt == null) {
                            if (tgtLocal != null) {
                                break;
                            }
                         } else {
                            break;
                        }
                    }
                    if (tgtStmt != null && tgtLocal != null) {
                        InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, true);
                    }
                }
            }
        }
        return uses;
    }

    private static void findUsesBackwardUtil(Body body, Stmt stmt, Local local, CallGraph cg, HashSet<SootMethod> handledMethods, List<UnitValueBoxPair> uses) {
        Iterator<Unit> intraDefs = IntraProcedureAnalysis.findDefs(body, stmt, local).iterator();
        while (intraDefs.hasNext()) {
            Unit intraDef = intraDefs.next();
            if (intraDef instanceof IdentityStmt) {
                Value identityRop = ((IdentityStmt) intraDef).getRightOp();
                if (!(identityRop instanceof ParameterRef)) {
                    logger.info("CASE-1: Right operator of IdentityStmt is not a ParameterRef instance.");
                    logger.info("{" + intraDef + "}");
                }else {
                    int index = ((ParameterRef) identityRop).getIndex();
                    Iterator<Edge> edges = cg.edgesInto(body.getMethod());
                    while (edges.hasNext()) {
                        Edge edge = edges.next();
                        SootMethod srcMethod = edge.src();
                        if (handledMethods.contains(srcMethod)) {
                            logger.info("CASE-1: Recursive invocation happens.");
                            logger.info("{" + srcMethod.getSignature() + "} will be called recursively.");
                        }else {
                            handledMethods.add(srcMethod);
                            Body srcBody = srcMethod.retrieveActiveBody();
                            Stmt srcStmt = edge.srcStmt();
                            Value srcArg = srcStmt.getInvokeExpr().getArg(index);
                            if (srcArg instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(srcBody, srcStmt, (Local) srcArg, cg, handledMethods, uses);
                            }else if(srcArg instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", srcArg.getType()), srcArg);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-1: Argument of the invocation is not a constant value or a local variable.");
                                logger.info("{" + srcStmt + "}");
                            }
                        }
                    }
                }
            }
            if (intraDef instanceof AssignStmt && ((AssignStmt) intraDef).containsInvokeExpr()) {
                SootMethod tgtMethod = ((AssignStmt) intraDef).getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-2: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will be called recursively.");
                }else if(tgtMethod.isConcrete()){
                    handledMethods.add(tgtMethod);
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    BriefUnitGraph briefUnitGraph = new BriefUnitGraph(tgtBody);
                    Iterator<Unit> tails = briefUnitGraph.getTails().iterator();
                    while (tails.hasNext()) {
                        Unit tail = tails.next();
                        if (tail instanceof ReturnStmt) {
                            ReturnStmt tgtStmt = (ReturnStmt) tail;
                            Value tgtValue = tgtStmt.getOp();
                            if (tgtValue instanceof Local) {
                                InterProcedureAnalysis.findUsesBackwardUtil(tgtBody, tgtStmt, (Local) tgtValue, cg, handledMethods, uses);
                            }else if(tgtValue instanceof Constant){
                                AssignStmt fakeStmt = Jimple.v().newAssignStmt(Jimple.v().newLocal("fakeLocal", tgtValue.getType()), tgtValue);
                                uses.add(new UnitValueBoxPair(fakeStmt, fakeStmt.getLeftOpBox()));
                            }else {
                                logger.info("CASE-2: The returned is not a constant value or a local variable.");
                                logger.info("{" + tgtStmt + "}");
                            }
                        }
                    }
                }
            }
        }
        Iterator<UnitValueBoxPair> iterator = IntraProcedureAnalysis.findUsesBackward(body, stmt, local, false).iterator();
        while (iterator.hasNext()) {
            uses.add(iterator.next());
        }
    }

    public static List<UnitValueBoxPair> findUsesForward(Body body, Stmt stmt, Local local, boolean isAssign) {
        HashSet<SootMethod> handledMethods = new HashSet<>();
        handledMethods.add(body.getMethod());
        CallGraph cg = Scene.v().getCallGraph();
        List<UnitValueBoxPair> uses = new ArrayList();

        Iterator<UnitValueBoxPair> pairs = IntraProcedureAnalysis.findUsesForward(body, stmt, local, isAssign).iterator();
        while (pairs.hasNext()) {
            UnitValueBoxPair pair = pairs.next();
            Stmt intraUse = (Stmt) pair.unit;
            uses.add(pair);
            if (intraUse.containsInvokeExpr() && (!(intraUse instanceof AssignStmt) || pair.getValueBox() != ((AssignStmt) intraUse).getLeftOpBox())) {
                SootMethod tgtMethod = intraUse.getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-1: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will call itself.");
                } else if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                    handledMethods.add(tgtMethod);
                    int argIndex = -1;
                    for (int index=0; index<intraUse.getInvokeExpr().getArgCount(); index++) {
                        if (pair.getValueBox() == intraUse.getInvokeExpr().getArgBox(index)) {
                            argIndex = index;
                        }
                    }
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    Stmt tgtStmt = null;
                    Local tgtLocal = null;
                    Iterator<Unit> units = tgtBody.getUnits().iterator();
                    while (units.hasNext()) {
                        Unit unit = units.next();
                        if (argIndex == -1) {
                            if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ThisRef) {
                                tgtStmt = (Stmt) unit;
                                tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                            }
                        } else if (unit instanceof IdentityStmt && (((IdentityStmt) unit).getRightOp() instanceof ParameterRef && ((ParameterRef) ((IdentityStmt) unit).getRightOp()).getIndex() == argIndex)){
                            tgtStmt = (Stmt) unit;
                            tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                        }

                        if (tgtStmt == null) {
                            if (tgtLocal != null) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    if (tgtStmt != null && tgtLocal != null) {
                        InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, isAssign);
                    }
                } else if (tgtMethod.isJavaLibraryMethod() && intraUse instanceof AssignStmt) {
                    Local tgtLocal = (Local) ((AssignStmt) intraUse).getLeftOp();
                    InterProcedureAnalysis.findUsesForwardUtil(body, intraUse, tgtLocal, cg, handledMethods, uses, isAssign);
                }
            }
            if (intraUse instanceof ReturnStmt) {
                Iterator<Edge> it = cg.edgesInto(body.getMethod());
                while (it.hasNext()) {
                    Edge edge = it.next();
                    SootMethod tgtMethod = edge.src();
                    if (handledMethods.contains(tgtMethod)) {
                        logger.info("CASE-1: Recursive invocation happens.");
                        logger.info("{" + tgtMethod.getSignature() + "} will be called recursively.");
                    } else if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                        handledMethods.add(tgtMethod);
                        Body tgtBody = tgtMethod.retrieveActiveBody();
                        Stmt tgtStmt = null;
                        Local tgtLocal = null;
                        Iterator<Unit> units = tgtBody.getUnits().iterator();
                        while (units.hasNext()) {
                            Unit unit = units.next();
                            if (unit instanceof AssignStmt && ((AssignStmt) unit).containsInvokeExpr()) {
                                SootMethod invokeMethod = ((AssignStmt) unit).getInvokeExpr().getMethod();
                                if (invokeMethod.getSignature().equals(edge.tgt().getSignature())) {
                                    tgtStmt = (Stmt) unit;
                                    tgtLocal = (Local) ((AssignStmt) unit).getLeftOp();
                                }
                            }
                            if (tgtStmt != null && tgtLocal != null) {
                                InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, true);
                                tgtStmt = null;
                                tgtLocal = null;
                            }
                        }
                    }
                }
            }
        }
        return uses;
    }

    private static void findUsesForwardUtil(Body body, Stmt stmt, Local local, CallGraph cg, HashSet<SootMethod> handledMethods, List<UnitValueBoxPair> uses, boolean isAssign) {
        Iterator<UnitValueBoxPair> pairs = IntraProcedureAnalysis.findUsesForward(body, stmt, local,isAssign).iterator();
        while (pairs.hasNext()) {
            UnitValueBoxPair pair = pairs.next();
            Stmt intraUse = (Stmt) pair.unit;
            uses.add(pair);
            if (intraUse.containsInvokeExpr() && (!(intraUse instanceof AssignStmt) || pair.getValueBox() != ((AssignStmt) intraUse).getLeftOpBox())) {
                SootMethod tgtMethod = intraUse.getInvokeExpr().getMethod();
                if (handledMethods.contains(tgtMethod)) {
                    logger.info("CASE-1: Recursive invocation happens.");
                    logger.info("{" + tgtMethod.getSignature() + "} will be called recursively.");
                } else if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()){
                    handledMethods.add(tgtMethod);
                    int argIndex = -1;
                    for (int index=0; index<intraUse.getInvokeExpr().getArgCount(); index++) {
                        if (pair.getValueBox() == intraUse.getInvokeExpr().getArgBox(index)) {
                            argIndex = index;
                        }
                    }
                    Body tgtBody = tgtMethod.retrieveActiveBody();
                    Stmt tgtStmt = null;
                    Local tgtLocal = null;
                    Iterator<Unit> units = tgtBody.getUnits().iterator();
                    while (units.hasNext()) {
                        Unit unit = units.next();
                        if (argIndex == -1) {
                            if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ThisRef) {
                                tgtStmt = (Stmt) unit;
                                tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                            }
                        } else if (unit instanceof IdentityStmt && ((IdentityStmt) unit).getRightOp() instanceof ParameterRef && ((ParameterRef) ((IdentityStmt) unit).getRightOp()).getIndex() == argIndex){
                            tgtStmt = (Stmt) unit;
                            tgtLocal = (Local) ((IdentityStmt) unit).getLeftOp();
                        }
                        if (tgtStmt == null) {
                            if (tgtLocal != null) {
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                    if (tgtStmt != null && tgtLocal != null) {
                        InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, true);
                    }
                }  else if (tgtMethod.isJavaLibraryMethod() && intraUse instanceof AssignStmt) {
                    Local tgtLocal = (Local) ((AssignStmt) intraUse).getLeftOp();
                    InterProcedureAnalysis.findUsesForwardUtil(body, intraUse, tgtLocal, cg, handledMethods, uses, isAssign);
                }
            }
            if (intraUse instanceof ReturnStmt) {
                Iterator<Edge> it = cg.edgesInto(body.getMethod());
                while (it.hasNext()) {
                    Edge edge = it.next();
                    SootMethod tgtMethod = edge.src();
                    if (handledMethods.contains(tgtMethod)) {
                        logger.info("CASE-1: Recursive invocation happens.");
                        logger.info("{" + tgtMethod.getSignature() + "} will be called recursively.");
                    } else if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                        handledMethods.add(tgtMethod);
                        Body tgtBody = tgtMethod.retrieveActiveBody();
                        Stmt tgtStmt = null;
                        Local tgtLocal = null;
                        Iterator<Unit> units = tgtBody.getUnits().iterator();
                        while (units.hasNext()) {
                            Unit unit = units.next();
                            if (unit instanceof AssignStmt && ((AssignStmt) unit).containsInvokeExpr()) {
                                SootMethod invokeMethod = ((AssignStmt) unit).getInvokeExpr().getMethod();
                                if (invokeMethod.getSignature().equals(edge.tgt().getSignature())) {
                                    tgtStmt = (Stmt) unit;
                                    tgtLocal = (Local) ((AssignStmt) unit).getLeftOp();
                                }
                            }
                            if (tgtStmt != null && tgtLocal != null) {
                                InterProcedureAnalysis.findUsesForwardUtil(tgtBody, tgtStmt, tgtLocal, cg, handledMethods, uses, true);
                                tgtStmt = null;
                                tgtLocal = null;
                            }
                        }
                    }
                }
            }
        }
    }
}

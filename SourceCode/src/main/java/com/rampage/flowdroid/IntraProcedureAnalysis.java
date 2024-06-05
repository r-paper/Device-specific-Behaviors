package com.rampage.flowdroid;

import soot.Body;
import soot.Local;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.*;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.SimpleLocalDefs;
import soot.toolkits.scalar.SimpleLocalUses;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.util.*;

public class IntraProcedureAnalysis {
    public static List<Unit> findDefs(Body body, Stmt stmt, Local local) {
        UnitGraph cfg = new BriefUnitGraph(body);
        SimpleLocalDefs simpleLocalDefs = new SimpleLocalDefs(cfg);
        List<Unit> defs = simpleLocalDefs.getDefsOfAt(local, stmt);
        return defs;
    }

    public static List<UnitValueBoxPair> findUses(Body body, Stmt stmt, Local local, boolean isAssign) {
        List<UnitValueBoxPair> uses = new ArrayList<>();
        UnitGraph cfg = new BriefUnitGraph(body);
        SimpleLocalDefs simpleLocalDefs = new SimpleLocalDefs(cfg);
        if (isAssign) {
            SimpleLocalUses simpleLocalUses = new SimpleLocalUses(cfg, simpleLocalDefs);
            List<UnitValueBoxPair> pairs = simpleLocalUses.getUsesOf(stmt);
            uses.addAll(pairs);
        }
        else {
            List<Unit> defs = simpleLocalDefs.getDefsOfAt(local, stmt);
            SimpleLocalUses simpleLocalUses = new SimpleLocalUses(cfg, simpleLocalDefs);
            for (Unit def: defs) {
                List<UnitValueBoxPair> pairs = simpleLocalUses.getUsesOf(def);
                uses.addAll(pairs);
            }
        }
        return uses;
    }

    public static List<UnitValueBoxPair> findUsesBackward(Body body, Stmt stmt, Local local, boolean isAssign) {
        UnitGraph cfg = new ExceptionalUnitGraph(body);
        HashSet<Unit> preUnits = new HashSet<>();
        Queue<Unit> queue = new LinkedList<>();
        queue.addAll(cfg.getPredsOf((Unit) stmt));
        while (!queue.isEmpty()) {
            Unit curUnit = queue.poll();
            if (!preUnits.contains(curUnit)) {
                preUnits.add(curUnit);
                for (Unit preUnit: cfg.getPredsOf(curUnit)) {
                    if (!preUnits.contains(preUnit) && !queue.contains(preUnit)) {
                        queue.add(preUnit);
                    }
                }
            }
        }
        List<UnitValueBoxPair> result = new ArrayList<>();
        List<UnitValueBoxPair> uses = findUses(body, stmt, local, isAssign);
        for (UnitValueBoxPair use: uses) {
            if (preUnits.contains(use.unit)) {
                result.add(use);
            }
        }
        return result;
    }

    public static List<UnitValueBoxPair> findUsesForward(Body body, Stmt stmt, Local local, boolean isAssign) {
        UnitGraph cfg = new BriefUnitGraph(body);
        LinkedHashSet<Unit> pstUnits = new LinkedHashSet<>();
        Queue<Unit> queue = new LinkedList<>();
        queue.addAll(cfg.getSuccsOf((Unit) stmt));
        while (!queue.isEmpty()) {
            Unit curUnit = queue.poll();
            if (!pstUnits.contains(curUnit)) {
                pstUnits.add(curUnit);
                for (Unit pstUnit: cfg.getSuccsOf(curUnit)) {
                    if (!pstUnits.contains(pstUnit) && !queue.contains(pstUnit)) {
                        queue.add(pstUnit);
                    }
                }
            }
        }
        List<UnitValueBoxPair> result = new ArrayList<>();
        List<UnitValueBoxPair> uses = findUses(body, stmt, local, isAssign);
        for (UnitValueBoxPair use: uses) {
            if (pstUnits.contains(use.unit)) {
                result.add(use);
                if (use.getUnit() instanceof AssignStmt) {
                    AssignStmt assignStmt = (AssignStmt) use.getUnit();
                    if (assignStmt.getRightOp() instanceof CastExpr) {
                        CastExpr castExpr = (CastExpr) assignStmt.getRightOp();
                        if (castExpr.getOp().equals(local)) {
                            Local tgtLocal = (Local) assignStmt.getLeftOp();
                            List<UnitValueBoxPair> useFur = findUsesForward(body, assignStmt, tgtLocal, isAssign);
                            result.addAll(useFur);
                        }
                    }
                }
                if (use.getUnit() instanceof IfStmt) {
                    IfStmt tgtStmt = (IfStmt) use.getUnit();
                    List<Unit> ifBody = Utils.retrieveIfBody(cfg, tgtStmt);
                    for (Unit ifStmt: ifBody) {
                        if (((Stmt) ifStmt).containsInvokeExpr()) {
                            SootMethod tgtMethod = ((Stmt) ifStmt).getInvokeExpr().getMethod();
                            if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                                Body tgtBody = tgtMethod.retrieveActiveBody();
                                Unit firstUnit = tgtBody.getUnits().getFirst();
                                if (!firstUnit.getUseBoxes().isEmpty()){
                                    result.add(new UnitValueBoxPair(firstUnit, firstUnit.getUseBoxes().get(0)));
                                }
                            }
                        }
                        if (((Stmt) ifStmt) instanceof ReturnStmt) {
                            result.add(new UnitValueBoxPair(ifStmt, ((ReturnStmt) ifStmt).getOpBox()));
                        }
                    }
                }
                if (use.getUnit() instanceof SwitchStmt) {
                    SwitchStmt switchStmt = (SwitchStmt) use.getUnit();
                    if (switchStmt.getKey().equals(local)) {
                        if (stmt.containsInvokeExpr() && stmt.getInvokeExpr().getMethod().getSignature().equals("<java.lang.String: int hashCode()>")) {
                            for (Unit tmpUnit: pstUnits) {
                                if (tmpUnit instanceof SwitchStmt) {
                                    if (tmpUnit.equals(switchStmt)) {
                                        continue;
                                    }
                                    SwitchStmt switchStmtReal = (SwitchStmt) tmpUnit;
                                    Set<Unit> switchBody = Utils.retrieveSwitchBody(cfg, switchStmtReal);
                                    for (Unit switchUnit: switchBody) {
                                        if (((Stmt) switchUnit).containsInvokeExpr()) {
                                            SootMethod tgtMethod = ((Stmt) switchUnit).getInvokeExpr().getMethod();
                                            if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                                                Body tgtBody = tgtMethod.retrieveActiveBody();
                                                Unit firstUnit = tgtBody.getUnits().getFirst();
                                                if (!firstUnit.getUseBoxes().isEmpty()){
                                                    result.add(new UnitValueBoxPair(firstUnit, firstUnit.getUseBoxes().get(0)));
                                                }
                                            }
                                        }
                                        if (((Stmt) switchUnit) instanceof ReturnStmt) {
                                            result.add(new UnitValueBoxPair(switchUnit, ((ReturnStmt) switchUnit).getOpBox()));
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        else {
                            Set<Unit> switchBody = Utils.retrieveSwitchBody(cfg, switchStmt);
                            for (Unit switchUnit: switchBody) {
                                if (((Stmt) switchUnit).containsInvokeExpr()) {
                                    SootMethod tgtMethod = ((Stmt) switchUnit).getInvokeExpr().getMethod();
                                    if (tgtMethod.isConcrete() && !tgtMethod.isJavaLibraryMethod()) {
                                        Body tgtBody = tgtMethod.retrieveActiveBody();
                                        Unit firstUnit = tgtBody.getUnits().getFirst();
                                        if (!firstUnit.getUseBoxes().isEmpty()){
                                            result.add(new UnitValueBoxPair(firstUnit, firstUnit.getUseBoxes().get(0)));
                                        }
                                    }
                                }
                                if (((Stmt) switchUnit) instanceof ReturnStmt) {
                                    result.add(new UnitValueBoxPair(switchUnit, ((ReturnStmt) switchUnit).getOpBox()));
                                }
                            }
                        }
                    }
                }
            }
        }
        return result;
    }
}

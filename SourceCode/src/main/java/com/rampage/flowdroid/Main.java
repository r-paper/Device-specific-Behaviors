package com.rampage.flowdroid;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.profiler.StopWatch;

import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.manifest.IContentProvider;
import soot.jimple.infoflow.solver.cfg.InfoflowCFG;
import soot.jimple.internal.AbstractStmt;
import soot.jimple.internal.JStaticInvokeExpr;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.scalar.UnitValueBoxPair;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.*;

public class Main {
    public static int number;
    protected static Logger logger = LoggerFactory.getLogger(Main.class.getClass());
    private static String splitor = "-------------------------------------------------\n";

    public static void main(String[] args) throws Exception{
        StopWatch stopWatch = new StopWatch("MyFlowdroid Analysis");
        stopWatch.start("MyFlowdroid Analysis");

        CommandLineOptions options = new CommandLineOptions(args);

        String apkPath = options.getApk();
        String jarPath = options.getPlatforms();

        Main.number = options.getNumber();

        File testFile = new File(options.getApk());
        if (!testFile.exists()) {
            logger.error("File not exists: " + options.getApk());
            System.exit(0);
        }

        File switchFile = new File(options.getOutputPath() + "switches/" + Main.number);
        if (!switchFile.createNewFile()) {
            logger.error("Create tag file failed: " + Main.number);
        }

        File processingFile = new File(Utils.addPrefix(options.getApk(), "0."));
        if (processingFile.exists()) {
            logger.error("Rename: file exists -- " + "0." + options.getApk());
        }
        if (testFile.renameTo(processingFile)) {
            logger.info("Rename: done -- " + "0." + options.getApk());
        }
        else {
            logger.error("Rename: failed -- " + "0." + options.getApk());
        }

            logger.info("DEBUG: file init operation complete");

        TimeOut timeOut = new TimeOut(options.getTimeout(), options.getOutputPath(), Utils.addPrefix(options.getApk(), "0."), options.getNumber());
        timeOut.trigger();

        G.reset();

        final InfoflowAndroidConfiguration config = Utils.flowdroidConfig(Utils.addPrefix(options.getApk(), "0."), jarPath);
        SetupApplication app = new SetupApplication(config);

        app.constructCallgraph();
        CallGraph callGraph = Scene.v().getCallGraph();

        InfoflowCFG icfg = new InfoflowCFG();

        Set<SootMethod> resultBuild = new HashSet<>();
        Set<SootMethod> resultReflection = new HashSet<>();
        Set<SootMethod> further = new HashSet<>();

        for (SootClass sootClass: Scene.v().getApplicationClasses()) {
            // filter class name
            for (Iterator<SootMethod> iterator = sootClass.methodIterator(); iterator.hasNext(); ) {
                SootMethod sootMethod = iterator.next();
                if (!sootMethod.hasActiveBody() || !sootMethod.isConcrete() || Utils.isLibraryMethod(sootMethod)) {
                    continue;
                }

                Body body = sootMethod.retrieveActiveBody();
                for (Unit unit : body.getUnits()) {
                    unit.apply(new AbstractStmtSwitch() {
                        public void caseAssignStmt(AssignStmt stmt) {
                            Value rop = stmt.getRightOp();
                            if (rop instanceof FieldRef) {
                                FieldRef fieldRef = (FieldRef) rop;
                                SootField sootField = fieldRef.getField();
                                String declaringClass = sootField.getDeclaringClass().getName();
                                if (declaringClass.startsWith("android.os.Build")) {
                                    resultBuild.add(sootMethod);
                                    List<UnitValueBoxPair> uses = InterProcedureAnalysis.findUsesForward(body, stmt, (Local) stmt.getLeftOp(), true);
                                    for (UnitValueBoxPair use: uses) {
                                        Unit tgtUnit = use.getUnit();
                                        resultBuild.add(icfg.getMethodOf(tgtUnit));
                                    }
                                }
                            }
                            if (rop instanceof StaticInvokeExpr) {
                                SootMethod callee = ((StaticInvokeExpr) rop).getMethod();
                                if (callee.getSignature().equals("<java.lang.Class: java.lang.Class forName(java.lang.String)>")) {
                                    if (stmt.getInvokeExpr().getArg(0) instanceof StringConstant) {
                                        if (((StringConstant) stmt.getInvokeExpr().getArg(0)).value.equals("android.os.SystemProperties")) {
                                            Local classLop = (Local) stmt.getLeftOp();
                                            List<UnitValueBoxPair> classUses = IntraProcedureAnalysis.findUsesForward(body, stmt, classLop, true);
                                            for (UnitValueBoxPair classUse: classUses) {
                                                Unit classUnit = classUse.getUnit();
                                                if (classUnit instanceof AssignStmt && ((AssignStmt) classUnit).getRightOp() instanceof InvokeExpr) {
                                                    SootMethod classInvokeMethod = ((InvokeExpr) ((AssignStmt) classUnit).getRightOp()).getMethod();
                                                    if (classInvokeMethod.getSignature().equals("<java.lang.Class: java.lang.reflect.Method getMethod(java.lang.String,java.lang.Class[])>")) {
                                                        Local methodLop = (Local) ((AssignStmt) classUnit).getLeftOp();
                                                        List<UnitValueBoxPair> methodUses = IntraProcedureAnalysis.findUsesForward(body, (Stmt) classUnit, methodLop, true);
                                                        for (UnitValueBoxPair methodUse: methodUses) {
                                                            Unit methodUnit = methodUse.getUnit();
                                                            if (methodUnit instanceof AssignStmt && ((AssignStmt) methodUnit).getRightOp() instanceof InvokeExpr) {
                                                                InvokeExpr methodInvokeExpr = (InvokeExpr) ((AssignStmt) methodUnit).getRightOp();
                                                                SootMethod methodInvokeMethod = methodInvokeExpr.getMethod();
                                                                if (methodInvokeMethod.getSignature().equals("<java.lang.reflect.Method: java.lang.Object invoke(java.lang.Object,java.lang.Object[])>")) {
                                                                    Local leftOp = (Local) ((AssignStmt) methodUnit).getLeftOp();
                                                                    List<UnitValueBoxPair> uses = InterProcedureAnalysis.findUsesForward(body, (Stmt) methodUnit, leftOp, true);
                                                                    for (UnitValueBoxPair use: uses) {
                                                                        Unit tgtUnit = use.getUnit();
                                                                        resultReflection.add(icfg.getMethodOf(tgtUnit));
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                } else if (callee.getDeclaringClass().equals("android.os.SystemProperties")) {
                                    further.add(sootMethod);
                                }
                            }
                        }
                    });
                }
            }
        }

        stopWatch.stop();

        try {
            BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(options.getOutputPath() + "time.txt", true));
            String logContent = Utils.getPackageName(Utils.addPrefix(options.getApk(), "0.")) + " -- " + String.valueOf(stopWatch.elapsedTime() / 1000000000) + "\n";
            bos.write(logContent.getBytes());
            bos.flush();
            bos.close();
            logger.info("Write time.txt done");
        } catch (Exception e) {
            logger.error("Write time.txt error\n" + e.getStackTrace());
        }

        // Result output
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(options.getOutputPath() + Utils.getPackageName(Utils.addPrefix(options.getApk(), "0."))));
        bos.write("--------------------ResultBuild--------------------\n".getBytes());
        for (SootMethod sootMethod: resultBuild) {
            if (sootMethod != null) {
                Body sinkBody = sootMethod.retrieveActiveBody();
                PatchingChain<Unit> units = sinkBody.getUnits();
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append(splitor).append(sootMethod.getSignature()).append(" Body:\n");
                for (Iterator<Unit> iterator = units.snapshotIterator(); iterator.hasNext();) {
                    Unit unit = iterator.next();
                    stringBuilder.append(unit.toString()).append("\n");
                }
                bos.write(stringBuilder.toString().getBytes());
            }
        }

        bos.write("--------------------ResultReflection--------------------\n".getBytes());
        for (SootMethod sootMethod: resultReflection) {
            if (sootMethod != null) {
                Body sinkBody = sootMethod.retrieveActiveBody();
                PatchingChain<Unit> units = sinkBody.getUnits();
                StringBuilder stringBuilder = new StringBuilder();
                stringBuilder.append(splitor).append(sootMethod.getSignature()).append(" Body:\n");
                for (Iterator<Unit> iterator = units.snapshotIterator(); iterator.hasNext();) {
                    Unit unit = iterator.next();
                    stringBuilder.append(unit.toString()).append("\n");
                }
                bos.write(stringBuilder.toString().getBytes());
            }
        }

        bos.write("--------------------FurtherAnalysis--------------------\n".getBytes());
        for (SootMethod sootMethod: further) {
            bos.write(sootMethod.getSignature().getBytes());
        }

        bos.flush();
        bos.close();

        // rename apk
        File processedFile = new File(Utils.addPrefix(options.getApk(), "1."));
        if (processedFile.exists()) {
            logger.error("Rename: file exists -- " + "1." + options.getApk());
        }
        if (processingFile.renameTo(processedFile)) {
            logger.info("Rename: done -- " + options.getApk() + " to .1 version");
        }
        else {
            logger.error("Rename: failed -- " + options.getApk() + ".0 to .1 version");
        }

        // spare instance number
        if (switchFile.delete()) {
            logger.info("Delete switch file done -- " + options.getOutputPath() + "switches/" + Main.number);
        }
        else {
            logger.error("Delete switch file failed -- " + options.getOutputPath() + "switches/" + Main.number);
        }

        logger.info("DEBUG: File stop operation complete and system exit");

        System.exit(0);
    }
}

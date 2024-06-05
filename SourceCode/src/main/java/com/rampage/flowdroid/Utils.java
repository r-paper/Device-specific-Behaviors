package com.rampage.flowdroid;

import org.xmlpull.v1.XmlPullParserException;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.manifest.ProcessManifest;
import soot.toolkits.graph.UnitGraph;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class Utils {
    public static String brandListPath = "D:\\Temp\\brand_list.txt";
    public static String osListPath = "D:\\Temp\\os_list.txt";
    public static String modelListPath = "D:\\Temp\\model_list.txt";

    public static List<String> brandList = new ArrayList<>();
    public static List<String> osList = new ArrayList<>();
    public static List<String> modelList = new ArrayList<>();


    public static InfoflowAndroidConfiguration flowdroidConfig(String apkPath, String jarPath) {
        final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setTargetAPKFile(apkPath);
        config.getAnalysisFileConfig().setAndroidPlatformDir(jarPath);

        config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
//        config.setEnableReflection(true);
        config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.SPARK);

        config.setMergeDexFiles(true);

        return config;
    }

    public static String getPackageName(String apkPath) {
        String packageName = "";
        try {
            ProcessManifest manifest = new ProcessManifest(apkPath);
            packageName = manifest.getPackageName();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (XmlPullParserException e) {
            e.printStackTrace();
        }
        return packageName;
    }

    public static void CallGraphFilter(String... filterContents) {
        List<SootClass> validClasses = new ArrayList<>();
        for (SootClass sootClass: Scene.v().getApplicationClasses()) {
            if (filterContents.length > 0) {
                boolean isSkip = true;
                for (String filterContent : filterContents) {
                    if (sootClass.getName().contains(filterContent)) {
                        isSkip = false;
                    }
                }
                if (sootClass.getName().endsWith(".R") || sootClass.getName().endsWith(".BuildConfig"))
                    isSkip = true;
                if (!isSkip)
                    validClasses.add(sootClass);
            }
            else {
                validClasses.add(sootClass);
            }
        }
    }

    public static List<Unit> retrieveIfBody(UnitGraph cfg, IfStmt ifStmt) {
        List<Unit> result = new ArrayList<>();
        Unit branchTrue = cfg.getSuccsOf(ifStmt).get(0);
        Unit branchFalse = null;
        if (cfg.getSuccsOf(ifStmt).size() > 1){
             branchFalse = cfg.getSuccsOf(ifStmt).get(1);
        }

        boolean isInIfBody = false;
        boolean isReturnInIfBody = false;
        for (Unit pstUnit: cfg.getBody().getUnits()) {
            if (pstUnit.equals(branchTrue)){
                isInIfBody = true;
            }
            if (pstUnit.equals(branchFalse) && !isReturnInIfBody) {
                break;
            }
            if (isInIfBody) {
                result.add(pstUnit);
                if (pstUnit instanceof ReturnStmt || pstUnit instanceof ReturnVoidStmt) {
                    isReturnInIfBody = true;
                }
            }
        }
        return result;
    }

    public static Set<Unit> retrieveSwitchBody(UnitGraph cfg, SwitchStmt switchStmt) {
        Set<Unit> result = new HashSet<>();
        List<Unit> gotoTarget = new ArrayList<>();
        for (Unit unit: switchStmt.getTargets()) {
            boolean isInSwitchBody = false;
            for (Unit pstUnit: cfg.getBody().getUnits()) {
                if (pstUnit.equals(unit)){
                    isInSwitchBody = true;
                }
                if (isInSwitchBody) {
                    if (pstUnit instanceof GotoStmt) {
                        GotoStmt gotoStmt = (GotoStmt) pstUnit;
                        gotoTarget.add(gotoStmt.getTarget());
                        break;
                    }
                    if (pstUnit instanceof ReturnStmt || pstUnit instanceof ReturnVoidStmt) {
                        break;
                    }
                }
            }
        }

        Unit endUnit = null;
        boolean isSure = false;
        if (gotoTarget.size() > 0) {
            Set<Unit> duplicates = findDuplicateUnits(gotoTarget);
            if (duplicates.size() == 1) {
                for (Unit unit: duplicates) {
                    endUnit = unit;
                    isSure = true;
                    break;
                }
            }
        }

        if (isSure && endUnit != null) {
            boolean isInSwitchBody = false;
            for (Unit pstUnit: cfg.getBody().getUnits()) {
                if (pstUnit.equals(switchStmt)){
                    isInSwitchBody = true;
                    continue;
                }
                if (isInSwitchBody) {
                    if (pstUnit.equals(endUnit)) {
                        break;
                    }
                    result.add(pstUnit);
                }
            }
        } else {
            for (Unit unit: switchStmt.getTargets()) {
                boolean isInSwitchBody = false;
                for (Unit pstUnit: cfg.getBody().getUnits()) {
                    if (pstUnit.equals(unit)){
                        isInSwitchBody = true;
                    }
                    if (isInSwitchBody) {
                        result.add(pstUnit);
                        if (pstUnit instanceof ReturnStmt || pstUnit instanceof ReturnVoidStmt) {
                            break;
                        }
                    }
                }
            }
        }
        return result;
    }

    public static boolean isLibraryMethod(SootMethod sootMethod) {
        String className = sootMethod.getDeclaringClass().getName();
        if (className.startsWith("android.os.SystemProperties")) {
            return false;
        }
        return className.startsWith("java.") || className.startsWith("sun.") || className.startsWith("javax.") || className.startsWith("com.sun.")
                || className.startsWith("org.omg.") || className.startsWith("org.xml.") || className.startsWith("org.w3c.dom")
                || className.startsWith("androidx.") || className.startsWith("android.");
    }

    public static String addPrefix(String filePath, String prefix) {
        File oldFile = new File(filePath);
        String fileName = oldFile.getName();
        return filePath.replace(fileName, prefix + fileName);
    }

    public static Set<Unit> findDuplicateUnits(List<Unit> units) {
        Set<Unit> duplicates = new HashSet<>();
        Set<Unit> total = new HashSet<>();

        // 统计元素出现的次数
        for (Unit unit: units) {
            if (!total.add(unit)) {
                duplicates.add(unit);
            }
        }
        return duplicates;
    }

    public static void loadDeviceInfoList() {
        try (BufferedReader reader = new BufferedReader(new FileReader(brandListPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                brandList.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(osListPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                osList.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        try (BufferedReader reader = new BufferedReader(new FileReader(modelListPath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                modelList.add(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    // model: 0 - normal, 1 - filter short name
    public static List<String> isBrandInContent(String content, int mode) {
        List<String> result = new ArrayList<>();
        content = content.toLowerCase();

        for (String brand: brandList) {
            brand = brand.toLowerCase();
            if (mode == 1) {
                if (brand.equals("blu") || brand.equals("bq") || brand.equals("cat") || brand.equals("lg")
                        || brand.equals("nec") || brand.equals("niu") || brand.equals("yu")) {
                    continue;
                }
            }
            if (content.contains(brand)) {
                result.add(brand);
            }
        }
        return result;
    }


    // model: 0 - normal, 1 - filter short name, 2 - strict equal
    public static List<String> isOsInContent(String content, int mode) {
        List<String> result = new ArrayList<>();
        content = content.toLowerCase();

        for (String osName : osList) {
            osName = osName.toLowerCase();

            if (mode == 1) {
                if (osName.equals("xos") || osName.equals("xui") || osName.equals("zui") || osName.equals("eui")) {
                    continue;
                }
            }

            if (mode == 2){
                if (content.equals(osName)) {
                    result.add(osName);
                    continue;
                }
                if (osName.contains(" ")) {
                    if (content.equals(osName.replace(" ", ""))) {
                        result.add(osName);
                        continue;
                    }
                    if (content.equals(osName.replace(" ", "_"))) {
                        result.add(osName);
                        continue;
                    }
                }
            }
            else {
                if (content.contains(osName)) {
                    result.add(osName);
                    continue;
                }
                if (osName.contains(" ")) {
                    if (content.contains(osName.replace(" ", ""))) {
                        result.add(osName);
                        continue;
                    }
                    if (content.contains(osName.replace(" ", "_"))) {
                        result.add(osName);
                        continue;
                    }
                }
            }
        }
        return result;
    }


    // mode: 0 - normal, 1 - filter short name, 2 - strict equal
    public static List<String> isModelInContent(String content, int mode) {
        List<String> result = new ArrayList<>();
        content = content.toLowerCase();

        for (String model: modelList) {
            model = model.toLowerCase();

            if (mode == 1) {
                if (model.length() < 4) {
                    continue;
                }
            }

            if (mode == 2) {
                if (content.equals(model)) {
                    result.add(model);
                }
            }
            else {
                if (content.contains(model)) {
                    result.add(model);
                }
            }
        }
        return result;
    }

    public static void main(String[] args) {
        loadDeviceInfoList();
    }
}

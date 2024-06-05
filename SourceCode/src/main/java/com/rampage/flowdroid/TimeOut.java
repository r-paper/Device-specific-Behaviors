package com.rampage.flowdroid;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class TimeOut {

    private Timer timer;
    private TimerTask exitTask = null;
    private int timeout;

    protected Logger logger = LoggerFactory.getLogger(this.getClass());

    public TimeOut(int n, String outputPath, String apkPath, int instanceNumber) {
        this.timer = new Timer();
        this.timeout = n != 0 ? n : 60;
        this.exitTask = new TimerTask() {
            @Override
            public void run() {
                logger.warn("Timeout reached !");
                logger.warn("Ending program...");
                try {
                    BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputPath + "time.txt", true));
                    String logContent = Utils.getPackageName(apkPath) + " -- timeout\n";
                    bos.write(logContent.getBytes());
                    bos.flush();
                    bos.close();
                    File oldFile = new File(apkPath);
                    File newFile = new File(Utils.addPrefix(apkPath, "2."));
                    if (newFile.exists()) {
                        logger.error("Rename: file exists -- " + apkPath + ".2");
                    }
                    if (oldFile.renameTo(newFile)) {
                        logger.info("Rename: done -- " + apkPath + " to .2 version");
                    }
                    else {
                        logger.error("Rename: failed -- " + apkPath + " to .2 version");
                    }

                    // spare instance number
                    File switchFile = new File(outputPath + "switches/" + instanceNumber);
                    if (switchFile.delete()) {
                        logger.info("Delete switch file done -- " + outputPath + "switches/" + instanceNumber);
                    }
                    else {
                        logger.error("Delete switch file failed -- " + outputPath + "switches/" + instanceNumber);
                    }
                    logger.info("DEBUG: file operation before exit complete");
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
                System.exit(0);
            }
        };
    }

    public void trigger() {
        Calendar c = Calendar.getInstance();
        c.add(Calendar.MINUTE, this.timeout);
        this.timer.schedule(this.exitTask, c.getTime());
    }

    public void cancel() {
        this.timer.cancel();
    }

    public int getTimeout() {
        return this.timeout;
    }
}

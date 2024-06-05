package com.rampage.flowdroid;

import org.apache.commons.cli.*;
import org.javatuples.Triplet;

public class CommandLineOptions {
    private static final Triplet<String, String, String> APK = new Triplet<String, String, String>("apk", "a", "Apk file");
    private static final Triplet<String, String, String> OUTPUT = new Triplet<String, String, String>("output", "o", "Output path");
    private static final Triplet<String, String, String> HELP = new Triplet<String, String, String>("help", "h", "Print this message");
    private static final Triplet<String, String, String> TIMEOUT = new Triplet<String, String, String>("timeout", "t", "Set the timeout for analysis");
    private static final Triplet<String, String, String> PLATFORMS = new Triplet<String, String, String>("platforms", "p", "Android platforms folder");
    private static final Triplet<String, String, String> NUMBER = new Triplet<String, String, String>("number", "n", "Instance number");
    private Options options, firstOptions;
    private CommandLineParser parser;
    private CommandLine commandLine, commandFirstLine;

    public CommandLineOptions(String[] args) {
        this.options = new Options();
        this.firstOptions = new Options();
        this.initOptions();
        this.parser = new DefaultParser();
        this.parse(args);
    }

    private void initOptions() {
        final Option apk = Option.builder(APK.getValue1())
                .longOpt(APK.getValue0())
                .desc(APK.getValue2())
                .hasArg(true)
                .argName(APK.getValue0())
                .required(true)
                .build();

        final Option outputPath = Option.builder(OUTPUT.getValue1())
                .longOpt(OUTPUT.getValue0())
                .desc(OUTPUT.getValue2())
                .hasArg(true)
                .argName(OUTPUT.getValue0())
                .required(true)
                .build();

        final Option timeout = Option.builder(TIMEOUT.getValue1())
                .longOpt(TIMEOUT.getValue0())
                .desc(TIMEOUT.getValue2())
                .hasArg(true)
                .argName(TIMEOUT.getValue0())
                .required(true)
                .build();

        final Option platforms = Option.builder(PLATFORMS.getValue1())
                .longOpt(PLATFORMS.getValue0())
                .desc(PLATFORMS.getValue2())
                .hasArg(true)
                .argName(PLATFORMS.getValue0())
                .required(true)
                .build();

        final Option help = Option.builder(HELP.getValue1())
                .longOpt(HELP.getValue0())
                .desc(HELP.getValue2())
                .argName(HELP.getValue0())
                .build();

        final Option number = Option.builder(NUMBER.getValue1())
                .longOpt(NUMBER.getValue0())
                .desc(NUMBER.getValue2())
                .hasArg(true)
                .argName(NUMBER.getValue0())
                .required(true)
                .build();

        this.firstOptions.addOption(help);

        this.options.addOption(apk);
        this.options.addOption(outputPath);
        this.options.addOption(platforms);
        this.options.addOption(timeout);
        this.options.addOption(number);

        for(Option o : this.firstOptions.getOptions()) {
            this.options.addOption(o);
        }
    }

    private void parse(String[] args) {
        HelpFormatter formatter = null;
        try {
            this.commandFirstLine = this.parser.parse(this.firstOptions, args, true);
            if (this.commandFirstLine.hasOption(HELP.getValue0())) {
                formatter = new HelpFormatter();
                formatter.printHelp("Pinduoduo", this.options, true);
                System.exit(0);
            }
            this.commandLine = this.parser.parse(this.options, args);
        } catch (ParseException e) {
            System.err.println(e.getMessage());
            System.exit(1);
        }
    }

    public String getApk() {
        return this.commandLine.getOptionValue(APK.getValue0());
    }

    public String getOutputPath() {
        return this.commandLine.getOptionValue(OUTPUT.getValue0());
    }

    public String getPlatforms() {
        return this.commandLine.getOptionValue(PLATFORMS.getValue0());
    }

    public int getTimeout() {
        return Integer.parseInt(this.commandLine.getOptionValue(TIMEOUT.getValue0()));
    }

    public int getNumber() {
        return Integer.parseInt(this.commandLine.getOptionValue(NUMBER.getValue0()));
    }
}

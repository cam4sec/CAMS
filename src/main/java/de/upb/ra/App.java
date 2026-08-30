package de.upb.ra;

import lombok.extern.slf4j.Slf4j;
import picocli.CommandLine;

import java.io.IOException;

/**
 * Main Class
 * -
 * ✨ Yesterday is a History, Tomorrow is a Mystery, but Today is a Gift ✨
 *              ✨ That is why it is called the Present. ✨
 *                                                 — Master Oogway
 *                                                 — Kung Fu Panda
 *
 * @author Ranjith K
 */
@Slf4j
public class App {
    public static void main(String[] args) throws IOException {
        int exitCode = new CommandLine(new CliArgParser()).execute(args);
        System.exit(exitCode);
    }
}

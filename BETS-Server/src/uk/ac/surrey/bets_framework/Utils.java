/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework;

import java.io.File;
import java.net.URL;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;

/**
 * Useful utility methods.
 *
 * @author Matthew Casey
 */
public class Utils {

  /** The extension given to a class file in Java. */
  private static final String CLASS_FILE_EXTENSION = ".class";

  /**
   * Recursive method to find all possible classes from the specified package name and its sub-packages. Modified from an example
   * at:
   * http://stackoverflow.com/questions/520328/can-you-find-all-classes-in-a-package-using-reflection
   *
   * @param directory The current directory being checked.
   * @param packageName The corresponding package.
   * @return A list of all the class in this package and down.
   * @throws ClassNotFoundException If a class was not found by its name.
   */
  private static List<Class<?>> findClasses(File directory, String packageName) throws ClassNotFoundException {
    final List<Class<?>> classes = new ArrayList<>();

    // Break the recursion if the directory does not exist.
    if (!directory.exists()) {
      return classes;
    }

    // Find all the files in this directory and add them to the list if they are classes, or recurse if they are sub-directories.
    final File[] files = directory.listFiles();

    for (final File file : files) {
      if (file.isDirectory()) {
        classes.addAll(findClasses(file, packageName + "." + file.getName()));
      }
      else if (file.getName().endsWith(CLASS_FILE_EXTENSION)) {
        classes.add(Class.forName(packageName + '.'
            + file.getName().substring(0, file.getName().length() - CLASS_FILE_EXTENSION.length())));
      }
    }

    return classes;
  }

  /**
   * Finds all possible classes from the top level package down. Modified from an example at:
   * http://stackoverflow.com/questions/520328/can-you-find-all-classes-in-a-package-using-reflection
   *
   * @param topPackage The top level package name to search down from.
   * @return A list of all classes in the top level package and down.
   */
  private static List<Class<?>> findClasses(String topPackage) {
    final List<Class<?>> classes = new ArrayList<>();

    try {
      // Get all of the packages in this top level package from the class loader.
      final ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
      final String path = topPackage.replace('.', '/');
      final Enumeration<URL> resources = classLoader.getResources(path);
      final List<File> directories = new ArrayList<File>();

      while (resources.hasMoreElements()) {
        final URL resource = resources.nextElement();
        directories.add(new File(resource.getFile()));
      }

      // Now find all the classes in these directories.
      for (final File directory : directories) {
        classes.addAll(findClasses(directory, topPackage));
      }
    }
    catch (final Exception e) {
      // Nothing we can do.
    }

    return classes;
  }

  /**
   * Gets the corresponding class from just its simple class name.
   *
   * @param topPackage The top level package name to search down from.
   * @param name The simple name of the class, without the package name.
   * @return The corresponding class object, or null if not found.
   */
  public static Class<?> getClass(String topPackage, String name) {
    Class<?> clazz = null;

    // Get all possible classes for the top level package and sub-packages.
    final List<Class<?>> classes = findClasses(topPackage);

    // See if we can find any class which matches.
    for (final Class<?> candidate : classes) {
      if (candidate.getSimpleName().equals(name)) {
        clazz = candidate;
      }
    }

    return clazz;
  }

  /**
   * Sets the Logback log level based upon an integer.
   *
   * @param logLevel The log level: 0 off to 6 all.
   */
  public static void setLogLevel(int logLevel) {
    // Set the log level to that required from the command line. This overrides the configuration file.
    final Logger logger = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    Level level = Level.ALL;

    switch (logLevel) {
      case 0:
        level = Level.OFF;
        break;

      case 1:
        level = Level.ERROR;
        break;

      case 2:
        level = Level.WARN;
        break;

      case 3:
        level = Level.INFO;
        break;

      case 4:
        level = Level.DEBUG;
        break;

      case 5:
        level = Level.TRACE;
        break;

      case 6:
      default:
        level = Level.ALL;
        break;

    }

    logger.setLevel(level);
  }

  /**
   * Converts a byte array to a hexadecimal string.
   *
   * @param array
   *          The byte array to convert.
   * @return The corresponding hexadecimal string.
   */
  public static String toHex(byte[] array) {
    String hex = null;

    if (array != null) {
      final StringBuilder result = new StringBuilder(array.length * 3); // Two digits and a separator.

      for (int i = 0; i < array.length; i++) {
        result.append(String.format("%02x%s", array[i], (i < (array.length - 1)) ? "-" : " "));
      }
      hex = result.toString().toUpperCase().trim();
    }

    return hex;
  }
}

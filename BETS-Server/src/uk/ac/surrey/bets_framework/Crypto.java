/**
 * DICE NFC evaluation.
 *
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.prng.VMPCRandomGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;

/**
 * Encapsulates all cryptographic operations as a singleton.
 *
 * @author Matthew Casey
 */
public class Crypto {

  /**
   * Extended Euclidean Algorithm in <code>BigInteger</code>s.
   *
   * Modified from:
   * https://github.com/bcgit/bc-java/blob/master/core/src/main/java/org/bouncycastle/pqc/math/ntru/euclid/BigIntEuclidean.java
   *
   * This is not available in the latest release of BouncyCastle because it sits in the NTRU package which has been removed from the
   * main bcprov JAR.
   */
  public static class BigIntEuclidean {

    /** The GCD. */
    public BigInteger gcd;

    /** The x factor. */
    public BigInteger x;

    /** The y factor. */
    public BigInteger y;

    /**
     * Runs the EEA on two <code>BigInteger</code>s<br>
     * Implemented from pseudocode on <a href="http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm">Wikipedia</a>.
     *
     * @param a The first value.
     * @param b The second value
     * @return a <code>BigIntEuclidean</code> object that contains the result in the variables <code>x</code>, <code>y</code>, and
     *         <code>gcd</code>
     */
    public static BigIntEuclidean calculate(BigInteger a, BigInteger b) {
      BigInteger x = BigInteger.ZERO;
      BigInteger lastx = BigInteger.ONE;
      BigInteger y = BigInteger.ONE;
      BigInteger lasty = BigInteger.ZERO;

      while (!b.equals(BigInteger.ZERO)) {
        final BigInteger[] quotientAndRemainder = a.divideAndRemainder(b);
        final BigInteger quotient = quotientAndRemainder[0];

        BigInteger temp = a;
        a = b;
        b = quotientAndRemainder[1];

        temp = x;
        x = lastx.subtract(quotient.multiply(x));
        lastx = temp;

        temp = y;
        y = lasty.subtract(quotient.multiply(y));
        lasty = temp;
      }

      final BigIntEuclidean result = new BigIntEuclidean();
      result.x = lastx;
      result.y = lasty;
      result.gcd = a;

      return result;
    }
  }

  /**
   * A PRNG SecureRandom implementation such that a seed is used to predictably generate a sequence of random numbers.
   */
  public static class PRNGSecureRandom extends SecureRandom {

    /** For serialisation. */
    private static final long serialVersionUID = 7427463362345309338L;

    /** The random number generator. */
    private RandomGenerator   generator        = null;

    /**
     * Constructor.
     *
     * @param seed The random number seed.
     */
    public PRNGSecureRandom(byte[] seed) {
      super();

      this.generator = new VMPCRandomGenerator();
      this.generator.addSeedMaterial(seed);
    }

    /**
     * Generates a user-specified number of random bytes.
     *
     * @param bytes the array to be filled in with random bytes.
     */
    @Override
    synchronized public void nextBytes(byte[] bytes) {
      this.generator.nextBytes(bytes);
    }
  }

  /** Default encryption parameters. */
  private static final String DEFAULT_ENCRYPTION_PARAMETERS = "RSA";

  /** Default hash parameters. */
  private static final String DEFAULT_HASH_PARAMETERS       = "SHA256";

  /** Default prime certainty. */
  private static final int    DEFAULT_PRIME_CERTAINTY       = 80;

  /** The singleton instance. */
  private static Crypto       instance                      = null;

  /** Key pair cipher. */
  private static final String KEY_PAIR_CIPHER               = "RSA";

  /** Logback logger. */
  private static final Logger LOG                           = LoggerFactory.getLogger(Crypto.class);

  /**
   * The seed used to initialise the random number generator. Set this to null to generate "deterministic" random numbers which is
   * useful for debugging purposes. Set this to something like Crypto.class.getSimpleName().getBytes() in production.
   */
  private static byte[]       PAIRING_RANDOM_SEED           = Crypto.class.getSimpleName().getBytes();

  /** The current set of DH parameters. May be pre-generated. */
  private DHParameters        dhParameters                  = null;

  /** Parameters used for encryption and decryption. */
  private String              encryptionParameters          = DEFAULT_ENCRYPTION_PARAMETERS;

  /** Parameters used for hashing. */
  private String              hashParameters                = DEFAULT_HASH_PARAMETERS;

  /** The key length. */
  private int                 keyLength                     = 0;

  /** The key pair. */
  private KeyPair             keyPair                       = null;

  /** The RSA encryption output block size: key length / 8. */
  private int                 outputBlockSize               = 0;

  /** The certainty in selecting a prime number when generating DSA parameters. */
  private int                 primeCertainty                = DEFAULT_PRIME_CERTAINTY;

  /** The remote requester/responder's public key. */
  private PublicKey           remotePublicKey               = null;

  /** The internally used random number generator */
  private SecureRandom        secRNG                        = null;

  
  /** The internal randomOracle hash functions  */
  
  private HashMap<String, Map<String, Element>> randomOracles = new HashMap<>();
  
  /** internal Base64 encoder */
  private Encoder base64 = Base64.getEncoder();
  
  /**
   * 
   * Private constructor.
   */
  private Crypto() {
    super();
    // Make sure we use BouncyCastle as the main security provider.
    // First remove the crippled version that is present in Android
    Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    // now insert the new one
    int index = Security.insertProviderAt(new BouncyCastleProvider(), 1);
    if (index != 1) {
      LOG.error("Could not install BouncyCastle - aborting!");
      throw new RuntimeException("Installation of BouncyCastle library failed!");
    }

    // Initialise the internal secure random number generator. Only use a deterministic RNG for testing.
    if (Crypto.PAIRING_RANDOM_SEED == null) {
      // This RNG will produce the same random numbers in each run.
      this.secRNG = new Crypto.PRNGSecureRandom("Debug purposes only".getBytes());
      LOG.debug("Using a deterministic random number generator");
    }
    else {
      // This RNG is truly random...
      this.secRNG = new SecureRandom(Crypto.PAIRING_RANDOM_SEED);
    }
  }

  /**
   * @return The singleton instance.
   */
  public static Crypto getInstance() {
    if (instance == null) {
      instance = new Crypto();
    }

    return instance;
  }

  /**
   * @param debug flag indicating whether a debug version of the Crypto class is required. If true, the random number generator will
   *          be deterministic across runs, ie it will produce the same sequence of "random" numbers
   * @return The singleton instance.
   */
  public static Crypto getInstance(boolean debug) {
    if (debug) {
      Crypto.PAIRING_RANDOM_SEED = null;
    }
    else {
      Crypto.PAIRING_RANDOM_SEED = Crypto.class.getSimpleName().getBytes();
    }
    return Crypto.getInstance();
  }

  /**
   * Performs an XOR on two byte arrays which may be of different sizes.
   *
   * @param data1 Byte array 1.
   * @param data2 Byte array 2.
   * @return The results of data1 XOR data2.
   */
  public static byte[] xor(byte[] data1, byte[] data2) {
    final byte[] result = new byte[Math.max(data1.length, data2.length)];
    byte[] operand = null;

    // Move the smallest array into the output so that we can XOR them.
    if (data1.length <= data2.length) {
      System.arraycopy(data1, 0, result, 0, data1.length);
      operand = data2;
    }
    else {
      System.arraycopy(data2, 0, result, 0, data2.length);
      operand = data1;
    }

    // Now perform the XOR.
    for (int i = 0; i < result.length; i++) {
      result[i] ^= operand[i];
    }

    return result;
  }

  /**
   * Decrypts the encrypted data using the specified key. Because RSA encryption has limited size that can be encrypted, the data
   * is therefore decrypted in blocks of the key length / 8.
   *
   * @param encrypted The encrypted data to decrypt.
   * @param key The encryption key.
   * @return The decrypted data, or null on error.
   */
  public byte[] decrypt(byte[] encrypted, Key key) {
    byte[] data = null;

    try {
      final Cipher cipher = Cipher.getInstance(this.encryptionParameters, BouncyCastleProvider.PROVIDER_NAME);
      cipher.init(Cipher.DECRYPT_MODE, key);

      // Decrypt the data in blocks.
      final int numBlocks = (int) Math.ceil((double) encrypted.length / (double) this.outputBlockSize);

      for (int i = 0; i < numBlocks; i++) {
        final byte[] decrypted = cipher.doFinal(encrypted, i * this.outputBlockSize, this.outputBlockSize);

        if (data == null) {
          data = decrypted;
        }
        else {
          final byte[] newData = Arrays.copyOf(data, data.length + decrypted.length);
          System.arraycopy(decrypted, 0, newData, data.length, decrypted.length);
          data = newData;
        }
      }
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException
        | IllegalBlockSizeException | InvalidKeyException | ArrayIndexOutOfBoundsException e) {
      LOG.error("could not decrypt data using local private key", e);
    }

    return data;
  }

  /**
   * Encrypts data using the specified key. Because RSA encryption has limited size that can be encrypted, the data is therefore
   * encrypted in blocks of an appropriate size for the algorithm and its padding. Here the data is split up into blocks
   * determined by the cipher, while the output size will always be the key length / 8.
   *
   * @param data The data to encrypt.
   * @param key The encryption key.
   * @return The encrypted data, or null on error.
   */
  public byte[] encrypt(byte[] data, Key key) {
    byte[] encrypted = null;

    try {
      final Cipher cipher = Cipher.getInstance(this.encryptionParameters, BouncyCastleProvider.PROVIDER_NAME);
      cipher.init(Cipher.ENCRYPT_MODE, key);

      // Encrypt the data in blocks.
      final int blockSize = cipher.getBlockSize();
      final int numBlocks = 1 + (data.length / blockSize);
      encrypted = new byte[numBlocks * this.outputBlockSize];

      for (int i = 0; i < numBlocks; i++) {
        final int length = Math.min((data.length - (i * blockSize)), blockSize);
        final byte[] block = cipher.doFinal(data, i * blockSize, length);
        System.arraycopy(block, 0, encrypted, i * this.outputBlockSize, this.outputBlockSize);
      }
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | BadPaddingException
        | IllegalBlockSizeException | InvalidKeyException | ArrayIndexOutOfBoundsException e) {
      LOG.error("could not encrypt data using remote public key, length {}: ", data.length, e);
    }

    return encrypted;
  }

  /**
   * Generates DH parameters - specifically a p and q being large primes with the required bit length such that p = 2q + 1 in
   * group g.
   */
  public void generateDHParameters() {
    final DHParametersGenerator generator = new DHParametersGenerator();
    generator.init(this.keyLength, this.primeCertainty, new SecureRandom());

    this.dhParameters = generator.generateParameters();
  }

  /**
   * @return The current set of DH parameters. May be pre-generated.
   */
  public DHParameters getDhParameters() {
    return this.dhParameters;
  }

  /**
   * @return Parameters used for encryption and decryption.
   */
  public String getEncryptionParameters() {
    return this.encryptionParameters;
  }

  /**
   * Produces a hash of the specified data.
   *
   * @param data The data to hash.
   * @param hashParameters the name of the hash algorithm to use
   * @return The hashed data.
   */
  public byte[] getHash(byte[] data, String hashParameters) {
    byte[] hash = null;

    try {
      final MessageDigest digest = MessageDigest.getInstance(hashParameters, BouncyCastleProvider.PROVIDER_NAME);
      digest.update(data);
      hash = digest.digest();
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      LOG.error("could not hash", e);
    }

    return hash;
  }

  
  /**
   * Produces a hash of the specified data.
   *
   * @param data The data to hash.
   * @param hashParameters the name of the hash algorithm to use
   * @param G the field to hash to
   * @return The hashed data.
   */
  public Element getHash(byte[] data, String[] hashParameters, Field<?> G) {
    Element hash = null;
    String key=base64.encodeToString(data);
    Map<String,Element> randomOracleHash=null;
    String hashName=hashParameters[1];
    LOG.debug("computing hash for data:"+key);
    
    if (hashParameters[0].equalsIgnoreCase("randomOracle")) {
    	if (randomOracles.containsKey(hashName)) {
    		LOG.debug("Found an existing hashmap for "+hashName);
    		randomOracleHash=randomOracles.get(hashName);
    	}else {
    		LOG.debug("Storing a new hashmap for "+hashName);
    		randomOracleHash=new HashMap<String,Element>();
    		randomOracles.put(hashName, randomOracleHash);
    	}
    	if (randomOracleHash.containsKey(key)) {
    		LOG.debug("match found for data- returning it");
    		return randomOracleHash.get(key);
    	}else {
    		LOG.debug("no match found for data- computing hash");
    		hash=G.newRandomElement().getImmutable();
    		randomOracleHash.put(key, hash);    	}
    }
    LOG.debug("returning hash: "+hash);
    return hash;
  }
  
  
  
  
  /**
   * Produces a hash of the specified data.
   * This uses the default hashing algorithm
   *
   * @param data The data to hash.
   * @return The hashed data.
   */

  public byte[] getHash(byte[] data) {
    return this.getHash(data, this.hashParameters);
  }

  /**
   * Generates a hash chain which consists of the specified data hashed iteration times. Each hash is on the previous hash output.
   *
   * @param data The original data to hash.
   * @param iteration The number of times the hash should be applied >= 0. When 0, no hash is applied.
   * @return The last hash in the hash chain.
   */
  public byte[] getHash(byte[] data, int iteration) {
    byte[] hash = data;

    for (int i = 0; i < iteration; i++) {
      hash = this.getHash(hash);
    }

    return hash;
  }

  /**
   * @return Parameters used for hashing.
   */
  public String getHashParameters() {
    return this.hashParameters;
  }

  /**
   * @return The key length.
   */
  public int getKeyLength() {
    return this.keyLength;
  }

  /**
   * Returns a key pair using the defined key length. Bult using:
   * https://www.txedo.com/blog/java-generate-rsa-keys-write-pem-file/
   *
   * @return The key pair.
   */
  public KeyPair getKeyPair() {
    if (this.keyPair == null) {
      try {
        final KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_PAIR_CIPHER, BouncyCastleProvider.PROVIDER_NAME);
        generator.initialize(this.keyLength);
        this.keyPair = generator.generateKeyPair();
      }
      catch (NoSuchAlgorithmException | NoSuchProviderException e) {
        LOG.error("could not generate key pair", e);
      }
    }

    return this.keyPair;
  }

  /**
   * @return The certainty in selecting a prime number when generating DSA parameters.
   */
  public int getPrimeCertainty() {
    return this.primeCertainty;
  }

  /**
   * @return The private key.
   */
  public PrivateKey getPrivateKey() {
    final KeyPair keyPair = this.getKeyPair();

    return keyPair.getPrivate();
  }

  /**
   * Generates a random array of bytes from a PRNG using the specified seed.
   *
   * @param seed The bytes to use as the seed.
   * @param length The number of bytes required.
   * @return An array of the next random bytes from the PRNG.
   */
  public byte[] getPRNGRandom(byte[] seed, int length) {
    final RandomGenerator generator = new VMPCRandomGenerator();
    generator.addSeedMaterial(seed);

    final byte[] bytes = new byte[length];
    generator.nextBytes(bytes);

    return bytes;
  }

  /**
   * @return The public key.
   */
  public PublicKey getPublicKey() {
    final KeyPair keyPair = this.getKeyPair();

    return keyPair.getPublic();
  }

  /**
   * @return The remote requester/responder's public key.
   */
  public PublicKey getRemotePublicKey() {
    return this.remotePublicKey;
  }

  /**
   * Generates a random big integer in the range 1 to maximum - 1. See:
   * http://stackoverflow.com/questions/2290057/how-to-generate-a-random-biginteger-value-in-java
   *
   * @param maximum The maximum (exclusive) value.
   * @return A random big integer in the range [1,maximum-1].
   */
  public BigInteger secureRandom(BigInteger maximum) {
    BigInteger random = new BigInteger(maximum.bitLength(), this.secRNG);

    while ((random.compareTo(maximum) >= 0) || (random.compareTo(BigInteger.ONE) <= 0)) {
      random = new BigInteger(maximum.bitLength(), this.secRNG);
    }

    return random;
  }

  /**
   * @param dhParameters The pre-generated set of DH parameters.
   */
  public void setDhParameters(DHParameters dhParameters) {
    this.dhParameters = dhParameters;
  }

  /**
   * Sets the default encryption parameters.
   */
  public void setEncryptionParameters() {
    this.encryptionParameters = DEFAULT_ENCRYPTION_PARAMETERS;
  }

  /**
   * @param encryptionParameters Parameters used for encryption and decryption.
   */
  public void setEncryptionParameters(String encryptionParameters) {
    this.encryptionParameters = encryptionParameters;
  }

  /**
   * Sets the default hash parameters.
   */
  public void setHashParameters() {
    this.hashParameters = DEFAULT_HASH_PARAMETERS;
  }

  /**
   * @param hashParameters Parameters used for hashing.
   */
  public void setHashParameters(String hashParameters) {
    this.hashParameters = hashParameters;
  }

  /**
   * Sets the key length.
   *
   * @param keyLength The key length.
   */
  public void setKeyLength(int keyLength) {
    this.keyLength = keyLength;
    this.outputBlockSize = keyLength / 8; // Always the same.
    this.keyPair = null;
  }

  /**
   * Sets the default prime certainty.
   */
  public void setPrimeCertainty() {
    this.primeCertainty = DEFAULT_PRIME_CERTAINTY;
  }

  /**
   * @param primeCertainty The certainty in selecting a prime number when generating DSA parameters.
   */
  public void setPrimeCertainty(int primeCertainty) {
    this.primeCertainty = primeCertainty;
  }

  public boolean isPrime(BigInteger p) {
    return p.isProbablePrime(this.primeCertainty);
  }

  /**
   * Sets the remote public key from an encoded byte array.
   *
   * @param bytes The encoded public key.
   */
  public void setRemotePublicKey(byte[] bytes) {
    try {
      final KeyFactory keyFactory = KeyFactory.getInstance(KEY_PAIR_CIPHER, BouncyCastleProvider.PROVIDER_NAME);
      this.remotePublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(bytes));
    }
    catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeySpecException e) {
      LOG.error("could not decode remote public key", e);
    }
  }
}
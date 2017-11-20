package uk.co.pervasive_intelligence.dice.protocol.ppetsfgp;

import org.bouncycastle.math.Primes;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParametersGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.pairing.parameters.PropertiesParameters;
import uk.co.pervasive_intelligence.dice.Crypto;

public class PPETSFGPSharedMemoryTest {

  @Test
  public void test() {
    byte[] PAIRING_RANDOM_SEED = ("A" + PPETSFGPSharedMemory.class.getSimpleName()).getBytes();
    SecureRandom RNG = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
    SecureRandom RNG2 = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);
    SecureRandom RNG3 = new Crypto.PRNGSecureRandom(PAIRING_RANDOM_SEED);

    PairingParametersGenerator<?> generator = new TypeACurveGenerator(
            RNG, 256, 512, false);
    PropertiesParameters pairingParameters = (PropertiesParameters) generator.generate();
    Pairing pairing = PairingFactory.getPairing(pairingParameters,
            RNG2);
    BigInteger p = pairingParameters.getBigInteger("r");
    System.out.println(pairingParameters);
    System.out.println(pairing);
    System.out.println(pairing.getDegree());
    System.out.println(pairing.getG1().getOrder());
    System.out.println(pairing.getG2().getOrder());
    System.out.println(pairing.getGT().getOrder());
    System.out.println(p);
    System.out.println(Primes.isMRProbablePrime(p, RNG3, 20));

  }

}

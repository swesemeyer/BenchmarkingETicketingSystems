/**
 * DICE NFC evaluation.
 * <p>
 * (c) University of Surrey and Pervasive Intelligence Ltd 2017.
 */
package uk.ac.surrey.bets_framework.protocol.ppetsfgp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import it.unisa.dia.gas.jpbc.Element;
import uk.ac.surrey.bets_framework.Crypto;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidCommand;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidSharedMemory;
import uk.ac.surrey.bets_framework.protocol.NFCAndroidState;
import uk.ac.surrey.bets_framework.protocol.data.Data;
import uk.ac.surrey.bets_framework.protocol.data.ListData;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.PPETSFGPSharedMemory.Actor;
import uk.ac.surrey.bets_framework.protocol.ppetsfgp.data.UserData;
import uk.ac.surrey.bets_framework.state.Action;
import uk.ac.surrey.bets_framework.state.Message;

/**
 * Ticket issuing states of the PPETS-FGP state machine protocol.
 *
 * @author Matthew Casey
 */
public class PPETSFGPIssuingStates {

  /**
   * Logback logger.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PPETSFGPIssuingStates.class);

  /**
   * State 6.
   */
  public static class IState06 extends NFCAndroidState {

    /**
     * Generates the user pseudonym data.
     *
     * @return The user pseudonym response data.
     */
    protected byte[] generateUserPseudonym() {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);
      final Crypto crypto = Crypto.getInstance();

      // Select random c_bar, d, d_bar, alpha, alpha_bar, alpha_bar_dash,
      // beta, x_bar_u,
      // r_bar_u, c_bar_u
      final BigInteger c_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger d = crypto.secureRandom(sharedMemory.p);
      final BigInteger d_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger alpha = crypto.secureRandom(sharedMemory.p);
      final BigInteger alpha_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger alpha_bar_dash = alpha.multiply(c_bar);
      final BigInteger beta = crypto.secureRandom(sharedMemory.p);
      final BigInteger beta_bar = crypto.secureRandom(sharedMemory.p);
      final BigInteger beta_bar_dash = beta.multiply(c_bar);
      final BigInteger x_bar_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger r_bar_u = crypto.secureRandom(sharedMemory.p);
      final BigInteger c_bar_u = crypto.secureRandom(sharedMemory.p);

      // Select random gamma_1-N1, gamma_bar_1-N1, a_bar_1-N1, and
      // t_1-N1_0-(k-1), t_dash_1-N1_0-(k-1), t_bar_1-N1_0-(k-1),
      // t_bar_dash_1-N1_0-(k-1), w_bar_1-N1_0-(k-1), w_bar_dash_1-N1_0-(k-1)
      final BigInteger[] gamma_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[] gamma_bar_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[] a_bar_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[][] t_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] t_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

      final BigInteger[][] t_bar_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] t_bar_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] w_bar_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] w_bar_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        gamma_n[i] = crypto.secureRandom(sharedMemory.p);
        gamma_bar_n[i] = crypto.secureRandom(sharedMemory.p);
        a_bar_n[i] = crypto.secureRandom(sharedMemory.p);

        for (int j = 0; j < sharedMemory.k; j++) {
          t_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
          t_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
          t_bar_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
          t_bar_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
          w_bar_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
          w_bar_dash_n_m[i][j] = crypto.secureRandom(sharedMemory.p);
        }
      }

      // Select random e_1-N2, e_bar_1-N2, e_hat_1-N2
      final BigInteger[] e_n = new BigInteger[sharedMemory.N2()];
      final BigInteger[] e_bar_n = new BigInteger[sharedMemory.N2()];
      final BigInteger[] e_hat_n = new BigInteger[sharedMemory.N2()];
      for (int i = 0; i < sharedMemory.N2(); i++) {
        e_n[i] = crypto.secureRandom(sharedMemory.p);
        e_bar_n[i] = crypto.secureRandom(sharedMemory.p);
        e_hat_n[i] = crypto.secureRandom(sharedMemory.p);
      }

      // Select random M_2_U
      final Element M_2_U = sharedMemory.pairing.getG1().newRandomElement().getImmutable();

      // Compute C = delta_U * theta^alpha
      final Element C = userData.delta_U.add(sharedMemory.theta.mul(alpha)).getImmutable();

      // Compute D = g^alpha * theta^beta
      final Element D = sharedMemory.g.mul(alpha).add(sharedMemory.theta.mul(beta)).getImmutable();

      // Compute phi = D^c_u=g^alpha_dash * theta^beta_dash where alpha_dash =
      // alpha*c_u and
      // beta_dash = beta*c_u
      final BigInteger alpha_dash = alpha.multiply(userData.c_u);
      final BigInteger beta_dash = beta.multiply(userData.c_u);
      // final Element phi =
      // sharedMemory.g.mul(alpha_dash).add(sharedMemory.theta.mul(beta_dash))

      final Element phi = D.mul(userData.c_u).getImmutable();
      // Compute Y = xi^x_u * g_1^d
      final Element Y = sharedMemory.xi.mul(userData.x_u).add(sharedMemory.g_n[1].mul(d)).getImmutable();

      // Compute:
      // Z_1-N1 = g^gamma_1-N1 * h^a_1-N1,
      // Z_dash_1-N1 = g^gamma_bar_1-N1 * h^a_bar_1-N1
      // Z_bar_1-N1 = g^gamma_bar_1-N1 *
      // PRODUCT_0-(k-1)(h_bar_i^w_bar_1-N1_0-(k-1))
      // Z_bar_dash_1-N1 = g^gamma_bar_1-N1 *
      // PRODUCT_0-(k-1)(h_bar_i^w_bar_dash_1-N1_0-(k-1))
      final Element[] Z_n = new Element[sharedMemory.N1()];
      final Element[] Z_dash_n = new Element[sharedMemory.N1()];
      final Element[] Z_bar_n = new Element[sharedMemory.N1()];
      final Element[] Z_bar_dash_n = new Element[sharedMemory.N1()];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        Z_n[i] = sharedMemory.g.mul(gamma_n[i]).add(sharedMemory.h.mul(UserData.A_U_range[i])).getImmutable();
        Z_dash_n[i] = sharedMemory.g.mul(gamma_bar_n[i]).add(sharedMemory.h.mul(a_bar_n[i]).getImmutable());

        Element sum1 = sharedMemory.g.mul(gamma_bar_n[i]).getImmutable();
        for (int j = 0; j < sharedMemory.k; j++) {
          final Element value = sharedMemory.h_bar_n[j].mul(w_bar_n_m[i][j]).getImmutable();
          sum1 = sum1.add(value).getImmutable();
        }
        Z_bar_n[i] = sum1.getImmutable();

        Element sum2 = sharedMemory.g.mul(gamma_bar_n[i]).getImmutable();
        for (int j = 0; j < sharedMemory.k; j++) {
          final Element value = sharedMemory.h_bar_n[j].mul(w_bar_dash_n_m[i][j]).getImmutable();
          sum2 = sum2.add(value).getImmutable();
        }
        Z_bar_dash_n[i] = sum2.getImmutable();
      }

      // Compute w_n_m and w_dash_n_m
      final int[][] w_n_m = new int[sharedMemory.N1()][sharedMemory.k];
      final int[][] w_dash_n_m = new int[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        // Calculate w_l_i member of [0, q-1], and since q = 2, w_l_i is
        // binary. Here w_l_i represents which bits are set in the
        // number A_U_range[i] - lower bound of range policy[i]
        final BigInteger lowerDiff = UserData.A_U_range[i].subtract(BigInteger.valueOf(sharedMemory.rangePolicies[i][0]));
        final String reverseLowerDiff = new StringBuilder(lowerDiff.toString(sharedMemory.q)).reverse().toString();

        // Calculate w_dash_l_i member of [0, q-1], and since q = 2,
        // w_dash_l_i is binary. Here w_dash_l_i represents which bits
        // are set in the number A_U_range[i] - upper bound of range
        // policy[i] + q^k
        final BigInteger upperDiff = UserData.A_U_range[i].subtract(BigInteger.valueOf(sharedMemory.rangePolicies[i][1]))
                .add(BigInteger.valueOf(sharedMemory.q).pow(sharedMemory.k));
        final String reverseUpperDiff = new StringBuilder(upperDiff.toString(sharedMemory.q)).reverse().toString();


        for (int j = 0; j < sharedMemory.k; j++) {
          if (j < reverseLowerDiff.length()) {
            w_n_m[i][j] = Integer.parseInt(Character.toString(reverseLowerDiff.charAt(j)));
          } else {
            w_n_m[i][j] = 0;
          }
          if (j < reverseUpperDiff.length()) {
            w_dash_n_m[i][j] = Integer.parseInt(Character.toString(reverseUpperDiff.charAt(j)));
          } else {
            w_dash_n_m[i][j] = 0;
          }
        }
      }

      // Compute:
      // A_w_1-N1_0-(k-1) = h_w_1-N1_0-(k-1)^t_1-N1_0-(k-1)
      // A_dash_w_1-N1_0-(k-1) = h_w_dash_1-N1_0-(k-1)^t_dash_1-N1_0-(k-1)
      // V_1-N1_0-(k-1) = e(h, h)^t_1-N1_0-(k-1) * e(A_w_1-N1_0-(k-1),
      // h)^-w_1-N1_0-(k-1)
      // V_bar_1-N1_0-(k-1) = e(h, h)^t_bar_1-N1_0-(k-1) * e(A_w_1-N1_0-(k-1),
      // h)^-w_bar_1-N1_0-(k-1)
      // V_dash_1-N1_0-(k-1) = e(h, h)^t_dash_1-N1_0-(k-1) *
      // e(A_dash_w_1-N1_0-(k-1), h)^-w_dash_1-N1_0-(k-1)
      // V_bar_dash_1-N1_0-(k-1) = e(h, h)^t_bar_dash_1-N1_0-(k-1) *
      // e(A_dash_w_1-N1_0-(k-1), h)^-w_bar_dash_1-N1_0-(k-1)
      final Element[][] A_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
      final Element[][] A_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
      final Element[][] V_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
      final Element[][] V_bar_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
      final Element[][] V_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];
      final Element[][] V_bar_dash_n_m = new Element[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        for (int j = 0; j < sharedMemory.k; j++) {
          A_n_m[i][j] = sharedMemory.h_n[w_n_m[i][j]].mul(t_n_m[i][j]).getImmutable();
          A_dash_n_m[i][j] = sharedMemory.h_n[w_dash_n_m[i][j]].mul(t_dash_n_m[i][j]).getImmutable();

          V_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_n_m[i][j]).mul(sharedMemory.pairing
                  .pairing(A_n_m[i][j], sharedMemory.h).pow(BigInteger.valueOf(w_n_m[i][j]).negate().mod(sharedMemory.p))).getImmutable();
          V_bar_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_bar_n_m[i][j])
                  .mul(sharedMemory.pairing.pairing(A_n_m[i][j], sharedMemory.h).pow(w_bar_n_m[i][j].negate().mod(sharedMemory.p)))
                  .getImmutable();

          V_dash_n_m[i][j] = (sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_dash_n_m[i][j]))
                  .mul(sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h)
                          .pow(BigInteger.valueOf(w_dash_n_m[i][j]).negate().mod(sharedMemory.p)))
                  .getImmutable();
          V_bar_dash_n_m[i][j] = sharedMemory.pairing.pairing(sharedMemory.h, sharedMemory.h).pow(t_bar_dash_n_m[i][j]).mul(
                  sharedMemory.pairing.pairing(A_dash_n_m[i][j], sharedMemory.h).pow(w_bar_dash_n_m[i][j].negate().mod(sharedMemory.p)))
                  .getImmutable();
        }
      }

      // Compute D_bar = g^alpha_bar * theta^beta_bar
      final Element D_bar = sharedMemory.g.mul(alpha_bar).add(sharedMemory.theta.mul(beta_bar)).getImmutable();

      // Compute phi_bar = D^c_bar
      final Element phi_bar = D.mul(c_bar).getImmutable();

      // Compute Y_bar = xi^x_bar_u * g_1^d_bar
      final Element Y_bar = sharedMemory.xi.mul(x_bar_u).add(sharedMemory.g_n[1].mul(d_bar)).getImmutable();

      // Compute:
      // R = e(C,g_bar) / e(g_0,g)
      // R_dash = e(xi,g)^x_bar_u * e(g_frak,g)^r_bar_u *
      // PRODUCT_1-N1(e(g_hat,g)^a_bar_l * PRODUCT_1-N2(e(eta_i,g)^e_hat_i * e
      // (C,g)^c_bar_u * e(theta,g)^a_bar_dash * e(theta,g_bar)^alpha_bar
      final Element R = sharedMemory.pairing.pairing(C, sharedMemory.g_bar)
              .div(sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.g)).getImmutable();
      final Element R_dash1 = sharedMemory.pairing.pairing(sharedMemory.xi, sharedMemory.g).pow(x_bar_u).getImmutable();
      final Element R_dash2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_bar_u).getImmutable();

      Element product1 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
      for (int i = 0; i < sharedMemory.N1(); i++) {
        final Element value = sharedMemory.pairing.pairing(sharedMemory.g_hat_n[i], sharedMemory.g).pow(a_bar_n[i]);
        product1 = product1.mul(value);
      }

      Element product2 = sharedMemory.pairing.getGT().newOneElement().getImmutable();
      ;
      for (int i = 0; i < sharedMemory.N2(); i++) {
        final Element value = sharedMemory.pairing.pairing(sharedMemory.eta_n[i], sharedMemory.g).pow(e_hat_n[i]);
        product2 = product2.mul(value);
      }

      final Element R_dash3 = sharedMemory.pairing.pairing(C, sharedMemory.g).pow(c_bar_u.negate().mod(sharedMemory.p));
      final Element R_dash4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(alpha_bar_dash);
      final Element R_dash5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(alpha_bar);

      final Element R_dash = R_dash1.mul(R_dash2).mul(product1).mul(product2).mul(R_dash3).mul(R_dash4).mul(R_dash5);

      // Compute:
      // B_1-N2_j = eta_1-N2_j^e_1-N2
      // W_1-N2_j = e(B_1-N2_j,eta_bar_1-N2)
      // W_bar_1-N2_j = e(eta,eta_1-N2)^e_bar_1-N2 *
      // e(B_1-N2_j,eta_1-N2)^e_hat_1-N2
      //
      // Note here we are only required to select one of the j set policies,
      // but for completeness, and to ensure that we measure
      // the maximum possible timing for the protocol, we have selected a
      // value for all possible set values zeta.
      final Element[][] B_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
      final Element[][] W_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];
      final Element[][] W_bar_n_m = new Element[sharedMemory.N2()][sharedMemory.zeta()];

      for (int i = 0; i < sharedMemory.N2(); i++) {
        for (int j = 0; j < sharedMemory.zeta(); j++) {
          if (UserData.A_U_set[i].equalsIgnoreCase(sharedMemory.setPolices[i][j])) {
            B_n_m[i][j] = sharedMemory.eta_n_n[i][j].mul(e_n[i]).getImmutable();
            W_n_m[i][j] = sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_bar_n[i]).getImmutable();
            Element part1 = sharedMemory.pairing.pairing(sharedMemory.eta, sharedMemory.eta_n[i]).pow(e_bar_n[i]).getImmutable();
            Element part2 = sharedMemory.pairing.pairing(B_n_m[i][j], sharedMemory.eta_n[i]).pow(e_hat_n[i]).getImmutable();
            W_bar_n_m[i][j] = part1.mul(part2).getImmutable();
          } else {
            // just stick some fixed element here... as they won't be used...
            B_n_m[i][j] = sharedMemory.g;
            W_n_m[i][j] = sharedMemory.g;
            W_bar_n_m[i][j] = sharedMemory.g;

          }
        }
      }

      // Calculate hash c_BAR
      final List<byte[]> c_BARList = new ArrayList<>();
      c_BARList.addAll(Arrays.asList(M_2_U.toBytes(), Y.toBytes(), Y_bar.toBytes(), D.toBytes(), D_bar.toBytes(), phi.toBytes(),
              phi_bar.toBytes(), C.toBytes(), R.toBytes(), R_dash.toBytes()));

      for (int i = 0; i < sharedMemory.N1(); i++) {
        c_BARList.add(Z_n[i].toBytes());
      }
      for (int i = 0; i < sharedMemory.N1(); i++) {
        c_BARList.add(Z_dash_n[i].toBytes());
      }

      for (int i = 0; i < sharedMemory.N2(); i++) {
        for (int j = 0; j < sharedMemory.zeta(); j++) {
          c_BARList.add(B_n_m[i][j].toBytes());
        }
      }
      for (int i = 0; i < sharedMemory.N2(); i++) {
        for (int j = 0; j < sharedMemory.zeta(); j++) {
          c_BARList.add(W_n_m[i][j].toBytes());
        }
      }

      for (int i = 0; i < sharedMemory.N2(); i++) {
        for (int j = 0; j < sharedMemory.zeta(); j++) {
          c_BARList.add(W_bar_n_m[i][j].toBytes());
        }
      }
      final ListData c_BARData = new ListData(c_BARList);
      final byte[] c_BAR = crypto.getHash(c_BARData.toBytes());
      final BigInteger c_BARNum = new BigInteger(1, c_BAR).mod(sharedMemory.p);

      // Compute:
      // x_BAR_u = x_bar_u - c_BAR * x_u
      // d_BAR = d_bar - c_BAR * d
      // r_BAR_u = r_bar_u - c_BAR * r_u
      final BigInteger x_BAR_u = x_bar_u.subtract(c_BARNum.multiply(userData.x_u)).mod(sharedMemory.p);

      final BigInteger d_BAR = d_bar.subtract(c_BARNum.multiply(d)).mod(sharedMemory.p);
      final BigInteger r_BAR_u = r_bar_u.subtract(c_BARNum.multiply(userData.r_u)).mod(sharedMemory.p);

      // Compute:
      // gammac_BAR_1-N1 = gamma_bar_1-N1 - c_BAR * gamma_1-N1
      // ac_BAR_1-N1 = a_bar_1-N1 - c_BAR * a_1-N1
      final BigInteger[] gammac_BAR_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[] ac_BAR_n = new BigInteger[sharedMemory.N1()];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        gammac_BAR_n[i] = gamma_bar_n[i].subtract(c_BARNum.multiply(gamma_n[i])).mod(sharedMemory.p);
        ac_BAR_n[i] = a_bar_n[i].subtract(c_BARNum.multiply(UserData.A_U_range[i])).mod(sharedMemory.p);
      }

      // Compute:
      // e_BAR_1-N2 = e_bar_1-N2 - c_BAR * e_1-N2
      // e_BAR_dash_1-N2 = e_hat_1-N2 - c_BAR * H(I_1-N2_j)
      final BigInteger[] e_BAR_n = new BigInteger[sharedMemory.N2()];
      final BigInteger[] e_BAR_dash_n = new BigInteger[sharedMemory.N2()];
      final BigInteger[] e_BAR_dash_dash_n = new BigInteger[sharedMemory.N2()];

      try {
        for (int i = 0; i < sharedMemory.N2(); i++) {
          e_BAR_n[i] = e_bar_n[i].subtract(c_BARNum.multiply(e_n[i])).mod(sharedMemory.p);

          final byte[] hash = crypto.getHash(UserData.A_U_set[i].getBytes(Data.UTF8));
          final BigInteger hashNum = new BigInteger(1, hash).mod(sharedMemory.p);

          e_BAR_dash_n[i] = e_hat_n[i].subtract(c_BARNum.multiply(hashNum)).mod(sharedMemory.p); // needed for R' verification
          e_BAR_dash_dash_n[i] = e_hat_n[i].add(c_BARNum.multiply(hashNum)).mod(sharedMemory.p); // needed for W_bar_n_m verification
        }
      } catch (final UnsupportedEncodingException e) {
        // Ignore.
      }

      // Compute:
      // c_BAR_u = c_bar_u - c_BAR * c_u
      // alpha_BAR = alpha_bar - c_BAR * alpha
      // beta_BAR = beta_bar - c_BAR * beta
      // alpha_BAR_dash = alpha_bar_dash - c_BAR * alpha_dash
      // beta_BAR_dash = beta_bar_dash - c_BAR * beta_dash
      final BigInteger c_BAR_u = c_bar_u.subtract(c_BARNum.multiply(userData.c_u)).mod(sharedMemory.p);
      final BigInteger alpha_BAR = alpha_bar.subtract(c_BARNum.multiply(alpha)).mod(sharedMemory.p);
      final BigInteger beta_BAR = beta_bar.subtract(c_BARNum.multiply(beta)).mod(sharedMemory.p);
      final BigInteger alpha_BAR_dash = alpha_bar_dash.subtract(c_BARNum.multiply(alpha_dash)).mod(sharedMemory.p);
      final BigInteger beta_BAR_dash = beta_bar_dash.subtract(c_BARNum.multiply(beta_dash)).mod(sharedMemory.p);

      // Compute hashes e_BAR_1-N1
      final byte[][] e_BAR_m = new byte[sharedMemory.N1()][];
      final BigInteger[] e_BAR_mNum = new BigInteger[sharedMemory.N1()];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        final ListData data = new ListData(
                Arrays.asList(M_2_U.toBytes(), Z_n[i].toBytes(), Z_dash_n[i].toBytes(), Z_bar_n[i].toBytes(), Z_bar_dash_n[i].toBytes()));
        e_BAR_m[i] = crypto.getHash(data.toBytes());
        e_BAR_mNum[i] = new BigInteger(1, e_BAR_m[i]).mod(sharedMemory.p);
      }

      // Compute:
      // gammae_BAR_1-N1 = gamma_bar_1-N1 - e_bar_1-N1 * gamma_1-N1
      // ae_BAR_1-N1 = a_bar_1-N1 - e_BAR_1-N1 * (a_1-N1 - c_1-N1)
      // ae_BAR_dash_1-N1 = a_bar_1-N1 - e_BAR_1-N1 * (a_1-N1 - d_k + q^k)
      final BigInteger[] gammae_BAR_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[] ae_BAR_n = new BigInteger[sharedMemory.N1()];
      final BigInteger[] ae_BAR_dash_n = new BigInteger[sharedMemory.N1()];
      final BigInteger limit = BigInteger.valueOf((long) Math.pow(sharedMemory.q, sharedMemory.k));

      for (int i = 0; i < sharedMemory.N1(); i++) {
        gammae_BAR_n[i] = (gamma_bar_n[i].subtract(e_BAR_mNum[i].multiply(gamma_n[i]))).mod(sharedMemory.p);

        final BigInteger lower = BigInteger.valueOf(sharedMemory.rangePolicies[i][0]);
        ae_BAR_n[i] = (a_bar_n[i].subtract(e_BAR_mNum[i].multiply(UserData.A_U_range[i].subtract(lower)))).mod(sharedMemory.p);

        final BigInteger upper = BigInteger.valueOf(sharedMemory.rangePolicies[i][1]);
        ae_BAR_dash_n[i] = a_bar_n[i].subtract(e_BAR_mNum[i].multiply(UserData.A_U_range[i].subtract(upper).add(limit)));

        // do some tests

      }

      // Compute:
      // we_BAR_1-N1_0-(k-1) = w_bar_1-N1_0-(k-1) - e_BAR_1-N1 *
      // w_1-N1_0-(k-1)
      // we_BAR_dash_1-N1_0-(k-1) = w_bar_dash_1-N1_0-(k-1) - e_BAR_1-N1 *
      // w_dash_1-N1_0-(k-1)
      final BigInteger[][] we_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] we_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        for (int j = 0; j < sharedMemory.k; j++) {
          we_BAR_n_m[i][j] = w_bar_n_m[i][j].subtract(e_BAR_mNum[i].multiply(BigInteger.valueOf(w_n_m[i][j]))).mod(sharedMemory.p);
          we_BAR_dash_n_m[i][j] = w_bar_dash_n_m[i][j].subtract(e_BAR_mNum[i].multiply(BigInteger.valueOf(w_dash_n_m[i][j])))
                  .mod(sharedMemory.p);
        }
      }

      // Compute hash d_BAR_1-N1_0-(k-1)
      final byte[][][] d_BAR_n_m = new byte[sharedMemory.N1()][sharedMemory.k][];
      final BigInteger[][] d_BAR_n_mNum = new BigInteger[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        for (int j = 0; j < sharedMemory.k; j++) {
          final ListData data = new ListData(Arrays.asList(M_2_U.toBytes(), A_n_m[i][j].toBytes(), A_dash_n_m[i][j].toBytes(),
                  V_n_m[i][j].toBytes(), V_dash_n_m[i][j].toBytes(), V_bar_n_m[i][j].toBytes(), V_bar_dash_n_m[i][j].toBytes()));
          d_BAR_n_m[i][j] = crypto.getHash(data.toBytes());
          d_BAR_n_mNum[i][j] = new BigInteger(1, d_BAR_n_m[i][j]).mod(sharedMemory.p);
        }
      }

      // Compute:
      // t_BAR_1-N1_0-(k-1) = t_bar_1-N1_0-(k-1) - d_BAR_1-N1_0-(k-1) *
      // t_1-N1_0-(k-1)
      // t_BAR_dash_1-N1_0-(k-1) = t_bar_dash_1-N1_0-(k-1) -
      // d_BAR_1-N1_0-(k-1) * t_dash_1-N1_0-(k-1)
      // wd_BAR_1-N1_0-(k-1) = w_bar_1-N1_0-(k-1) - d_BAR_1-N1_0-(k-1) *
      // w_1-N1_0-(k-1)
      // wd_BAR_dash_1-N1_0-(k-1) = w_bar_dash_1-N1_0-(k-1) -
      // d_BAR_1-N1_0-(k-1) * w_dash_1-N1_0-(k-1)
      final BigInteger[][] t_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] t_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] wd_BAR_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];
      final BigInteger[][] wd_BAR_dash_n_m = new BigInteger[sharedMemory.N1()][sharedMemory.k];

      for (int i = 0; i < sharedMemory.N1(); i++) {
        for (int j = 0; j < sharedMemory.k; j++) {
          t_BAR_n_m[i][j] = t_bar_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(t_n_m[i][j])).mod(sharedMemory.p);
          t_BAR_dash_n_m[i][j] = t_bar_dash_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(t_dash_n_m[i][j])).mod(sharedMemory.p);
          wd_BAR_n_m[i][j] = w_bar_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(BigInteger.valueOf(w_n_m[i][j])))
                  .mod(sharedMemory.p);
          wd_BAR_dash_n_m[i][j] = w_bar_dash_n_m[i][j].subtract(d_BAR_n_mNum[i][j].multiply(BigInteger.valueOf(w_dash_n_m[i][j])))
                  .mod(sharedMemory.p);
        }
      }

      // Save d, Y for later.
      userData.d = d;
      userData.Y = Y;

      // Send PI_2_U, which includes Y.
      final List<byte[]> sendDataList = new ArrayList<>();
      sendDataList.addAll(
              Arrays.asList(M_2_U.toBytes(), C.toBytes(), D.toBytes(), phi.toBytes(), Y.toBytes(), R.toBytes(), R_dash.toBytes()));

      for (int i = 0; i < sharedMemory.N1(); i++) {
        sendDataList.add(Z_n[i].toBytes());
        sendDataList.add(Z_dash_n[i].toBytes());
        sendDataList.add(Z_bar_n[i].toBytes());
        sendDataList.add(Z_bar_dash_n[i].toBytes());

        for (int j = 0; j < sharedMemory.k; j++) {
          sendDataList.add(A_n_m[i][j].toBytes());
          sendDataList.add(A_dash_n_m[i][j].toBytes());
          sendDataList.add(V_n_m[i][j].toBytes());
          sendDataList.add(V_bar_n_m[i][j].toBytes());
          sendDataList.add(V_dash_n_m[i][j].toBytes());
          sendDataList.add(V_bar_dash_n_m[i][j].toBytes());
        }
      }

      for (int i = 0; i < sharedMemory.N2(); i++) {
        for (int j = 0; j < sharedMemory.zeta(); j++) {
          sendDataList.add(B_n_m[i][j].toBytes());
          sendDataList.add(W_n_m[i][j].toBytes());
          sendDataList.add(W_bar_n_m[i][j].toBytes());
        }
      }

      sendDataList.add(c_BAR);
      sendDataList.add(c_BAR_u.toByteArray());
      sendDataList.add(x_BAR_u.toByteArray());
      sendDataList.add(d_BAR.toByteArray());
      sendDataList.add(r_BAR_u.toByteArray());
      sendDataList.add(alpha_BAR.toByteArray());
      sendDataList.add(beta_BAR.toByteArray());
      sendDataList.add(alpha_BAR_dash.toByteArray());
      sendDataList.add(beta_BAR_dash.toByteArray());

      for (int i = 0; i < sharedMemory.N1(); i++) {
        sendDataList.add(e_BAR_m[i]);

        sendDataList.add(gammac_BAR_n[i].toByteArray());
        sendDataList.add(ac_BAR_n[i].toByteArray());

        sendDataList.add(gammae_BAR_n[i].toByteArray());
        sendDataList.add(ae_BAR_n[i].toByteArray());
        sendDataList.add(ae_BAR_dash_n[i].toByteArray());
      }

      for (int i = 0; i < sharedMemory.N2(); i++) {
        sendDataList.add(e_BAR_n[i].toByteArray());
        sendDataList.add(e_BAR_dash_n[i].toByteArray());
        sendDataList.add(e_BAR_dash_dash_n[i].toByteArray());
      }

      for (int i = 0; i < sharedMemory.N1(); i++) {
        for (int j = 0; j < sharedMemory.k; j++) {
          sendDataList.add(d_BAR_n_m[i][j]);
          sendDataList.add(t_BAR_n_m[i][j].toByteArray());
          sendDataList.add(t_BAR_dash_n_m[i][j].toByteArray());
          sendDataList.add(we_BAR_n_m[i][j].toByteArray());
          sendDataList.add(we_BAR_dash_n_m[i][j].toByteArray());

          sendDataList.add(wd_BAR_n_m[i][j].toByteArray());
          sendDataList.add(wd_BAR_dash_n_m[i][j].toByteArray());
        }
      }

      final ListData sendData = new ListData(sendDataList);
      return sendData.toBytes();
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      // We are now the user.
      ((PPETSFGPSharedMemory) this.getSharedMemory()).actAs(Actor.USER);

      if (message.getType() == Message.Type.DATA) {
        // Verify the seller's proof.
        if (message.getData() != null) {
          if (this.verifySellerProof(message.getData())) {
            // Generate the user pseudonym data.
            byte[] data = this.generateUserPseudonym();

            if (data != null) {
              LOG.debug("generate seller pseudonym complete");

              // Save the data for the corresponding GET.
              ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = data;
              return new Action<>(Action.Status.END_SUCCESS, 7, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
            }
          }
        }
      }

      return super.getAction(message);
    }

    /**
     * Verifies the returned seller's proof.
     *
     * @return True if the verification is successful.
     */
    private boolean verifySellerProof(byte[] data) {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final Crypto crypto = Crypto.getInstance();

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 20) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final Element M_2_S = sharedMemory.curveElementFromBytes(listData.getList().get(0));

      final Element Q = sharedMemory.curveElementFromBytes(listData.getList().get(1));
      final Element Z = sharedMemory.curveElementFromBytes(listData.getList().get(2));
      final Element gamma = sharedMemory.curveElementFromBytes(listData.getList().get(3));
      // Ignore Z_dash
      // Ignore gamma_dash
      final Element omega = sharedMemory.gtFiniteElementFromBytes(listData.getList().get(6));
      // Ignore omega_dash

      final byte[] c_bar_1 = listData.getList().get(8);
      final BigInteger c_bar_1Num = new BigInteger(1, c_bar_1).mod(sharedMemory.p);

      final byte[] c_bar_2 = listData.getList().get(9);
      final BigInteger c_bar_2Num = new BigInteger(1, c_bar_2).mod(sharedMemory.p);

      final byte[] c_bar_3 = listData.getList().get(10);
      final BigInteger c_bar_3Num = new BigInteger(1, c_bar_3).mod(sharedMemory.p);

      final BigInteger s_bar_1 = new BigInteger(listData.getList().get(11));
      final BigInteger s_bar_2 = new BigInteger(listData.getList().get(12));

      final BigInteger s_hat_1 = new BigInteger(listData.getList().get(13));
      final BigInteger s_hat_2 = new BigInteger(listData.getList().get(14));

      final BigInteger r_bar_1 = new BigInteger(listData.getList().get(15));
      final BigInteger r_bar_2 = new BigInteger(listData.getList().get(16));
      final BigInteger r_bar_3 = new BigInteger(listData.getList().get(17));
      final BigInteger r_bar_4 = new BigInteger(listData.getList().get(18));
      final BigInteger r_bar_5 = new BigInteger(listData.getList().get(19));

      // Verify c_bar_1 = H(M_2_S || Z || g^s_bar_1 * theta^s_bar_2 *
      // Z^c_bar_1)
      final Element check1 = sharedMemory.g.mul(s_bar_1).add(sharedMemory.theta.mul(s_bar_2)).add(Z.mul(c_bar_1Num));
      final ListData c_bar_1VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), Z.toBytes(), check1.toBytes()));
      final byte[] c_bar_1Verify = crypto.getHash(c_bar_1VerifyData.toBytes());

      if (!Arrays.equals(c_bar_1, c_bar_1Verify)) {
        LOG.error("failed to verify PI_2_S: c_bar_1");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_1");

      // Verify c_bar_2 = H(M_2_S || gamma || g^s_hat_1 * theta^s_hat_2 *
      // gamma^c_bar_2)
      final Element check2 = sharedMemory.g.mul(s_hat_1).add(sharedMemory.theta.mul(s_hat_2)).add(gamma.mul(c_bar_2Num));
      final ListData c_bar_2VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), gamma.toBytes(), check2.toBytes()));
      final byte[] c_bar_2Verify = crypto.getHash(c_bar_2VerifyData.toBytes());

      if (!Arrays.equals(c_bar_2, c_bar_2Verify)) {
        LOG.error("failed to verify PI_2_S: c_bar_2");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_2");
      // Verify c_bar_3 = H(M_2_S || omega || e(rho,g)^r_bar_1 *
      // e(g_frak,g)^r_bar_2 * e(Q,g)^-r_bar_3 * e(theta,g)^r_bar_4 * e
      // (theta,g_bar)^r_bar_5 * omega^c_bar_3)
      final Element check3_1 = sharedMemory.pairing.pairing(sharedMemory.rho, sharedMemory.g).pow(r_bar_1).getImmutable();
      final Element check3_2 = sharedMemory.pairing.pairing(sharedMemory.g_frak, sharedMemory.g).pow(r_bar_2).getImmutable();
      final Element check3_3 = sharedMemory.pairing.pairing(Q, sharedMemory.g).pow(r_bar_3.negate().mod(sharedMemory.p))
              .getImmutable();
      final Element check3_4 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g).pow(r_bar_4).getImmutable();
      final Element check3_5 = sharedMemory.pairing.pairing(sharedMemory.theta, sharedMemory.g_bar).pow(r_bar_5).getImmutable();

      final Element check3_6 = omega.pow(c_bar_3Num).getImmutable();
      final Element check3 = check3_1.mul(check3_2).mul(check3_3).mul(check3_4).mul(check3_5).mul(check3_6).getImmutable();

      final ListData c_bar_3VerifyData = new ListData(Arrays.asList(M_2_S.toBytes(), omega.toBytes(), check3.toBytes()));
      final byte[] c_bar_3Verify = crypto.getHash(c_bar_3VerifyData.toBytes());

      if (!Arrays.equals(c_bar_3, c_bar_3Verify)) {
        LOG.error("failed to verify PI_2_S: c_bar_3");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }
      LOG.debug("SUCCESS: passed verification of PI_2_S: c_bar_3");
      return true;
    }
  }

  /**
   * State 7.
   */
  public static class IState07 extends NFCAndroidState {

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Send back the delayed response if we have a GET.
        if (message.getData() == null) {
          byte[] data = ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse;
          ((NFCAndroidSharedMemory) this.getSharedMemory()).delayedResponse = null;

          if (data != null) {
            byte[] response = this.addResponseCode(data, NFCAndroidSharedMemory.RESPONSE_OK);
            return new Action<>(Action.Status.END_SUCCESS, 8, NFCAndroidCommand.RESPONSE, response, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }

  /**
   * State 8.
   */
  public static class IState08 extends NFCAndroidState {

    /**
     * Verifies the returned ticket serial number data.
     *
     * @return True if the verification is successful.
     */
    private boolean verifyTicketSerialNumber(byte[] data) {
      // Note that all elliptic curve calculations are in an additive group such that * -> + and ^ -> *.
      final PPETSFGPSharedMemory sharedMemory = (PPETSFGPSharedMemory) this.getSharedMemory();
      final UserData userData = (UserData) sharedMemory.getData(Actor.USER);

      // Decode the received data.
      final ListData listData = ListData.fromBytes(data);

      if (listData.getList().size() != 9) {
        LOG.error("wrong number of data elements: " + listData.getList().size());
        return false;
      }

      final Element T_U = sharedMemory.curveElementFromBytes(listData.getList().get(0));
      final BigInteger d_dash = new BigInteger(listData.getList().get(1));
      final BigInteger omega_u = new BigInteger(listData.getList().get(2));
      final byte[] s_u = listData.getList().get(3);
      final BigInteger s_uNum = new BigInteger(1, s_u);
      final Element Y_S = sharedMemory.curveElementFromBytes(listData.getList().get(4));
      byte[] time = listData.getList().get(5);
      byte[] service = listData.getList().get(6);
      byte[] price = listData.getList().get(7);
      byte[] validPeriod = listData.getList().get(8);

      // Compute d_u = d + d_dash
      final BigInteger d_u = userData.d.add(d_dash);

      // Check that e(T_U, Y_S * rho^omega_u) =? e(g_0,rho) * e(Y,rho) *
      // e(g_1,rho)^d_u * e(g_2,rho)^s_u
      final Element left = sharedMemory.pairing.pairing(T_U, Y_S.add(sharedMemory.rho.mul(omega_u))).getImmutable();

      final Element right1 = sharedMemory.pairing.pairing(sharedMemory.g_n[0], sharedMemory.rho).getImmutable();
      final Element right2 = sharedMemory.pairing.pairing(userData.Y_U, sharedMemory.rho).getImmutable();
      final Element right3 = sharedMemory.pairing.pairing(sharedMemory.g_n[1], sharedMemory.rho).pow(d_u).getImmutable();
      final Element right4 = sharedMemory.pairing.pairing(sharedMemory.g_n[2], sharedMemory.rho).pow(s_uNum).getImmutable();

      if (!left.isEqual(right1.mul(right2).mul(right3).mul(right4))) {
        LOG.error("failed to verify e(T_U, Y_S * rho^omega_u)");
        if (!sharedMemory.passVerification) {
          return false;
        }
      }

      // Keep the ticket Ticket_U = (d_u, d_dash, s_u, omega_u, T_U, Time, Service, Price, Valid_Period).
      userData.d_u = d_u;
      userData.d_dash = d_dash;
      userData.s_u = s_u;
      userData.omega_u = omega_u;
      userData.T_U = T_U.getImmutable();
      userData.Y_S = Y_S.getImmutable();
      userData.time = time;
      userData.service = service;
      userData.price = price;
      userData.validPeriod = validPeriod;

      LOG.debug("SUCCESS: verified Ticket serial number");

      return true;
    }

    /**
     * Gets the required action given a message.
     *
     * @param message The received message to process.
     * @return The required action.
     */
    @Override
    public Action<NFCAndroidCommand> getAction(Message message) {
      if (message.getType() == Message.Type.DATA) {
        // Verify the ticket serial number.
        if (message.getData() != null) {
          if (this.verifyTicketSerialNumber(message.getData())) {
            LOG.debug("verify ticket serial number complete");
            return new Action<>(Action.Status.END_SUCCESS, 9, NFCAndroidCommand.RESPONSE, NFCAndroidSharedMemory.RESPONSE_OK, 0);
          }
        }
      }

      return super.getAction(message);
    }
  }
}

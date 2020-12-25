package eg.alexu.edu.RSA;

import java.math.BigInteger;
import java.util.*;

public class TimingAttack {

    public static final String ANSI_BLUE = "\u001B[34m";
    public static final String ANSI_RESET = "\u001B[0m";

    private final Montgomery montgomery;

    private final int MAX = 10000;

    private final int MAX_ITERATION = 20;

    private final int[] PRIVATE_KEY_LENGTHS = {3, 5, 10, 20, 50, 100};

    private final Random RANDOM = new Random();

    private boolean oneBit_reduction = false, zeroBit_reduction = false;

    private long oneBitWithReduction, oneBitWithoutReduction, zeroBitWithReduction, zeroBitWithoutReduction;

    public TimingAttack(Montgomery montgomery) {
        this.montgomery  = montgomery;
    }

    private void simulate_2nd_bit_effect(BigInteger decryptedMessage, BigInteger updatedPrivateKey, BigInteger mod) {
        BigInteger commonStep = this.montgomery.montgomery_algorithm(decryptedMessage, decryptedMessage, mod);
        BigInteger oneStep = this.montgomery.montgomery_algorithm(commonStep, decryptedMessage, mod);
        this.oneBit_reduction = this.montgomery_algorithm_check(oneStep, oneStep, mod);
        this.zeroBit_reduction = this.montgomery_algorithm_check(commonStep, commonStep, mod);
    }

    public Boolean montgomery_algorithm_check(BigInteger number1, BigInteger number2, BigInteger modulus) {
        BigInteger t = number1.multiply(number2);
        BigInteger m = t.multiply(this.montgomery.inv_modulus).and(this.montgomery.r_value.subtract(BigInteger.ONE));
        t = t.add(m.multiply(modulus)).shiftRight(modulus.bitLength());
        return t.compareTo(modulus) >= 0;
    }

    public long convert_avg(long submission) {
        return submission / this.MAX;
    }

    public void remove() {
        oneBitWithReduction = oneBitWithoutReduction = zeroBitWithReduction = zeroBitWithoutReduction = 0;
    }

    public void start(BigInteger public_key, BigInteger private_key, BigInteger mod) {
        int okay = 0, total_success = 0;
        for (int no_of_bits : PRIVATE_KEY_LENGTHS) {
            BigInteger updatedPrivateKey = new BigInteger(private_key.toString(2).substring(0, no_of_bits), 2);
            okay = 0;
            for (int tests = 0; tests < this.MAX_ITERATION; ++tests) {
                remove();
                for (int i = 0; i < this.MAX; ++i) {
                    BigInteger decryptedMessage = this.montgomery.montgomery_converter(new BigInteger(mod.bitLength() - 1, RANDOM), mod);

                    simulate_2nd_bit_effect(decryptedMessage, updatedPrivateKey, mod);

                    long time = System.nanoTime();
                    this.montgomery.decrypt(decryptedMessage, updatedPrivateKey, mod);
                    time = System.nanoTime() - time;

                    if (this.oneBit_reduction)
                        this.oneBitWithReduction += time;
                    else
                        this.oneBitWithoutReduction += time;

                    if (this.zeroBit_reduction)
                        this.zeroBitWithReduction += time;
                    else
                        this.zeroBitWithoutReduction += time;
                }

                if ((this.convert_avg(this.oneBitWithReduction) - this.convert_avg(this.oneBitWithoutReduction)) >
                        (this.convert_avg(this.zeroBitWithReduction) - this.convert_avg(this.zeroBitWithoutReduction))) {
                    System.out.println(ANSI_BLUE + "There's a success in " + tests + " in length " + no_of_bits + ANSI_RESET);
                    ++okay;
                } else {
                    System.err.println("There's a failure in " + tests + " in length " + no_of_bits);
                }
            }
            total_success += okay;
        }
        System.out.println("Total success is = " + total_success);
        System.out.println("Accuracy = " + total_success * 100 / (this.PRIVATE_KEY_LENGTHS.length * this.MAX_ITERATION) + " % .");
    }
}

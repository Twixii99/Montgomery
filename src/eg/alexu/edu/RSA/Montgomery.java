package eg.alexu.edu.RSA;

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class Montgomery {

    private BigInteger r_value;
    private BigInteger inv_r_value;
    private BigInteger inv_modulus;

    public Montgomery(BigInteger modulus) {
        this.r_value = new BigInteger("1").shiftLeft(modulus.bitLength());
        this.inv_r_value = this.r_value.modInverse(modulus);
        this.inv_modulus = modulus.modInverse(this.r_value).multiply(new BigInteger("-1"));
    }

    public BigInteger encrypt(BigInteger plain_message, BigInteger public_key, BigInteger modulus) {
        return this.fast_modular_exponentiation(plain_message, public_key, modulus);
    }

    public BigInteger decrypt(BigInteger cipher_message, BigInteger public_key, BigInteger modulus) {
        return this.fast_modular_exponentiation(cipher_message, public_key, modulus);
    }

    private BigInteger montgomery_converter(BigInteger number, BigInteger modulus) {
        return number.multiply(this.r_value.mod(modulus)).mod(modulus);
    }

    private BigInteger inverse_montgomery_converter(BigInteger motgomerySpaceNumber, BigInteger modulus) {
        return (motgomerySpaceNumber.multiply(this.inv_r_value)).mod(modulus);
    }

    private BigInteger fast_modular_exponentiation(BigInteger message, BigInteger exponent, BigInteger modulus) {
        BigInteger mont_message = this.montgomery_converter(message, modulus);
        BigInteger result = mont_message;
        for (int i = exponent.bitLength() - 2; i >= 0; i--) {
            result = this.montgomery_algorithm(result, result, modulus);
            if (exponent.testBit(i)) {
                result = this.montgomery_algorithm(result, mont_message, modulus);
            }
        }
        return this.inverse_montgomery_converter(result, modulus);
    }

    private BigInteger montgomery_algorithm(BigInteger number1, BigInteger number2, BigInteger modulus) {
        BigInteger t = number1.multiply(number2);
        BigInteger m = t.multiply(this.inv_modulus).and(this.r_value.subtract(BigInteger.ONE));
        t = t.add(m.multiply(modulus)).shiftRight(modulus.bitLength());
        return t.compareTo(modulus) < 0 ? t : t.subtract(modulus);
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while(true) {
            BigInteger mess = scanner.nextBigInteger(), exp = scanner.nextBigInteger(), mod = scanner.nextBigInteger();
            Montgomery montgomery = new Montgomery(mod);
            System.out.println(montgomery.encrypt(mess, exp, mod));
        }
    }
}

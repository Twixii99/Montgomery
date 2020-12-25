package eg.alexu.edu.RSA;

import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class Montgomery {

    public BigInteger r_value;
    public BigInteger inv_r_value;
    public BigInteger inv_modulus;

    public Montgomery(BigInteger modulus) {
        this.r_value = BigInteger.ONE.shiftLeft(modulus.bitLength());
        this.inv_r_value = this.r_value.modInverse(modulus);
        this.inv_modulus = modulus.modInverse(this.r_value).multiply(new BigInteger("-1"));
    }

    public BigInteger encrypt(BigInteger plain_message, BigInteger public_key, BigInteger modulus) {
        return this.fast_modular_exponentiation(plain_message, public_key, modulus);
    }

    public BigInteger decrypt(BigInteger cipher_message, BigInteger private_key, BigInteger modulus) {
        return this.fast_modular_exponentiation(cipher_message, private_key, modulus);
    }

    public BigInteger montgomery_converter(BigInteger number, BigInteger modulus) {
        return number.shiftLeft(modulus.bitLength()).mod(modulus);
    }

    public BigInteger inverse_montgomery_converter(BigInteger montgomerySpaceNumber, BigInteger modulus) {
        return (montgomerySpaceNumber.multiply(this.inv_r_value)).mod(modulus);
    }

    public BigInteger montgomery_algorithm(BigInteger number1, BigInteger number2, BigInteger modulus) {
        BigInteger t = number1.multiply(number2);
        BigInteger m = t.multiply(this.inv_modulus).and(this.r_value.subtract(BigInteger.ONE));
        t = t.add(m.multiply(modulus)).shiftRight(modulus.bitLength());
        if(t.compareTo(modulus) < 0) return t;
        for(int i = 0; i < 100; ++i)
            t.add(modulus).subtract(modulus);
        return t.subtract(modulus);
    }

    public BigInteger fast_modular_exponentiation(BigInteger message, BigInteger exponent, BigInteger modulus) {
        BigInteger result = message;
        for (int i = exponent.bitLength() - 2; i >= 0; i--) {
            result = this.montgomery_algorithm(result, result, modulus);
            if (exponent.testBit(i))
                result = this.montgomery_algorithm(result, message, modulus);
        }
        return result;
    }
}

package gwyneth.programme.securealgorithm;

import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.google.android.material.textfield.TextInputLayout;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class MainActivity extends AppCompatActivity {
    TextInputLayout editPlaintext, editEncrypt, result;
    Button btnEncrypt, btnDecrypt;
    TextView txtInfo;
    BigInteger plaintext, encrypted, sharedKey;

    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final int bitLength = 256;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setControl();
        setEvent();
    }

    private void setEvent() {
        sharedKey = DiffieHellman.sharedKDH;

        btnEncrypt.setOnClickListener(view -> {
            String message = editPlaintext.getEditText().getText().toString();
            editPlaintext.clearFocus();

            if (!message.isEmpty()) {
                plaintext = new BigInteger(message.getBytes());
                // Step 5: Alice and Bob use the shared secret key K to encrypt and decrypt a message using RSA
                encrypted = rsaEncrypt(plaintext, sharedKey);
                System.out.println("Encrypt message: " + encrypted);
                result.getEditText().getText().clear();
                result.getEditText().setText(String.valueOf(encrypted));
            } else {
                Toast.makeText(this, "Please enter plaintext!", Toast.LENGTH_SHORT).show();
            }
        });

        btnDecrypt.setOnClickListener(view -> {
            String message = editEncrypt.getEditText().getText().toString();
            BigInteger encryptText = new BigInteger(message);
            editEncrypt.clearFocus();

            if (!message.isEmpty()) {
                BigInteger decrypted = rsaDecrypt(encryptText, sharedKey);
                System.out.println("Decrypt message: " + decrypted);
                result.getEditText().getText().clear();
                result.getEditText().setText(new String(decrypted.toByteArray(), StandardCharsets.UTF_8));
            } else {
                Toast.makeText(this, "Please enter encrypted text!", Toast.LENGTH_SHORT).show();
            }
        });
    }

    // RSA encryption function (publicKey, moduleN)
    public static BigInteger rsaEncrypt(BigInteger message, BigInteger sharedKey) {
        return message.modPow(sharedKey, RSA.N);
    }

    // RSA decryption function (privateKey, moduleN)
    public static BigInteger rsaDecrypt(BigInteger message, BigInteger sharedKey) {
        while (sharedKey.compareTo(RSA.phi) >= 0 || !sharedKey.gcd(RSA.phi).equals(ONE)) {
            sharedKey = sharedKey.add(ONE);
        }
        return message.modPow(sharedKey.modInverse(RSA.phi), RSA.N);
    }

    // Get Shared Key by Diffie-Hellman algorithm
    public static class DiffieHellman {
        private static final SecureRandom random = new SecureRandom();
        public static BigInteger sharedKDH;

        static {
            // Step 1: Choose a large prime number p and a primitive root g mod p
            BigInteger pDH = BigInteger.probablePrime(bitLength, random); // large prime number
            BigInteger gDH = BigInteger.valueOf(2); // primitive root of p

            // Step 2: Choose a secret random number a and b, respectively
            BigInteger priADH = new BigInteger(bitLength, random);
            BigInteger priBDH = new BigInteger(bitLength, random);

            // Step 3: Exchange public keys A and B, respectively
            BigInteger pubADH = gDH.modPow(priADH, pDH);
            BigInteger pubBDH = gDH.modPow(priBDH, pDH);

            // Step 4: Compute the shared secret key K
            BigInteger K_Alice = pubBDH.modPow(priADH, pDH);
            BigInteger K_Bob = pubADH.modPow(priBDH, pDH);

            // Verify that the shared secret key K is the same for Alice and Bob
            if (K_Alice.equals(K_Bob)) {
                System.out.println("Shared secret key K: " + K_Alice);
                sharedKDH = K_Alice;
            } else {
                System.out.println("Error: Shared secret key K does not match.");
            }
        }
    }

    // RSA key generation class
    public static class RSA {
        private static final SecureRandom random = new SecureRandom();
        public static BigInteger N, phi;

        static {
            BigInteger p = BigInteger.probablePrime(bitLength, random);
            BigInteger q = BigInteger.probablePrime(bitLength, random);
            N = p.multiply(q);
            phi = (p.subtract(ONE)).multiply(q.subtract(ONE));
        }
    }

    private void setControl() {
        editPlaintext = findViewById(R.id.editPlaintext);
        editEncrypt = findViewById(R.id.editEncrypt);
        result = findViewById(R.id.editResult);
        btnEncrypt = findViewById(R.id.btnEncrypt);
        btnDecrypt = findViewById(R.id.btnDecrypt);
//        txtInfo = findViewById(R.id.txtInfo);
    }
}
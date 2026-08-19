package com.loxvault.app;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.view.View;
import android.widget.*;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class MainActivity extends Activity {

    private static final int PICK_FILE = 10;
    private static final int CREATE_FILE = 11;

    private static final byte[] MAGIC =
            "LOXENC01".getBytes(StandardCharsets.US_ASCII);

    private static final int VERSION = 1;
    private static final int KDF_ARGON2ID = 1;
    private static final int CIPHER_AES256_GCM = 1;

    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int KEY_LEN = 32;

    private static final int TIME_COST = 3;
    private static final int MEMORY_KIB = 64 * 1024;
    private static final int PARALLELISM = 2;

    private Uri selected;
    private boolean decryptMode;

    private EditText password;
    private TextView fileName, status;
    private ProgressBar progress;
    private Button encrypt, decrypt;

    private final SecureRandom rng = new SecureRandom();

    @Override
    public void onCreate(Bundle state) {
        super.onCreate(state);

        setContentView(R.layout.activity_main);

        fileName = findViewById(R.id.fileName);
        status = findViewById(R.id.status);
        password = findViewById(R.id.password);
        progress = findViewById(R.id.progress);

        encrypt = findViewById(R.id.encryptButton);
        decrypt = findViewById(R.id.decryptButton);

        findViewById(R.id.selectButton)
                .setOnClickListener(v -> chooseFile());

        encrypt.setOnClickListener(v -> start(false));
        decrypt.setOnClickListener(v -> start(true));
    }

    private void chooseFile() {
        Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);

        i.setType("*/*");
        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        startActivityForResult(i, PICK_FILE);
    }

    private void start(boolean decrypt) {

        if (selected == null) {
            toast("Select a file first.");
            return;
        }

        String pw = password.getText().toString();

        if (pw.isEmpty()) {
            toast("Enter a password.");
            return;
        }

        decryptMode = decrypt;

        Intent i = new Intent(Intent.ACTION_CREATE_DOCUMENT);

        i.addCategory(Intent.CATEGORY_OPENABLE);
        i.setType("application/octet-stream");

        String name = displayName(selected);

        if (decrypt) {

            if (name.endsWith(".enc")) {
                name = name.substring(0, name.length() - 4);
            } else {
                name = name + ".decrypted";
            }

        } else {

            if (!name.endsWith(".enc")) {
                name = name + ".enc";
            }
        }

        i.putExtra(Intent.EXTRA_TITLE, name);

        startActivityForResult(i, CREATE_FILE);
    }

    @Override
    protected void onActivityResult(
            int req,
            int result,
            Intent data) {

        super.onActivityResult(req, result, data);

        if (result != RESULT_OK || data == null) {
            return;
        }

        if (req == PICK_FILE) {

            selected = data.getData();

            try {
                getContentResolver()
                        .takePersistableUriPermission(
                                selected,
                                Intent.FLAG_GRANT_READ_URI_PERMISSION
                        );
            } catch (Exception ignored) {
            }

            fileName.setText(
                    "Selected: " + displayName(selected)
            );

        } else if (req == CREATE_FILE) {

            doCrypto(data.getData());
        }
    }

    private void doCrypto(Uri output) {

        final Uri input = selected;
        final String pw = password.getText().toString();

        setBusy(true);

        new Thread(() -> {

            try {

                byte[] in = readAll(input);

                byte[] out = decryptMode
                        ? decrypt(in, pw)
                        : encrypt(in, pw);

                try (
                        OutputStream os =
                                getContentResolver()
                                        .openOutputStream(output, "w")
                ) {

                    if (os == null) {
                        throw new IOException(
                                "Cannot open output"
                        );
                    }

                    os.write(out);
                }

                runOnUiThread(() -> {

                    setBusy(false);

                    status.setText(
                            (decryptMode
                                    ? "Decrypted"
                                    : "Encrypted")
                                    + " successfully • "
                                    + out.length
                                    + " bytes"
                    );
                });

            } catch (AEADBadTagException e) {

                fail(
                        "Authentication failed: wrong password or modified file."
                );

            } catch (Exception e) {

                fail(
                        e.getClass().getSimpleName()
                                + ": "
                                + e.getMessage()
                );
            }

        }).start();
    }

    private byte[] encrypt(
            byte[] plaintext,
            String password
    ) throws Exception {

        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];

        rng.nextBytes(salt);
        rng.nextBytes(nonce);

        byte[] key = derive(
                password,
                salt,
                TIME_COST,
                MEMORY_KIB,
                PARALLELISM
        );

        byte[] header = header(
                TIME_COST,
                MEMORY_KIB,
                PARALLELISM,
                salt,
                nonce
        );

        Cipher c =
                Cipher.getInstance("AES/GCM/NoPadding");

        c.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce)
        );

        c.updateAAD(header);

        byte[] ct = c.doFinal(plaintext);

        byte[] all =
                new byte[header.length + ct.length];

        System.arraycopy(
                header,
                0,
                all,
                0,
                header.length
        );

        System.arraycopy(
                ct,
                0,
                all,
                header.length,
                ct.length
        );

        return Base64.getEncoder().encode(all);
    }

    private byte[] decrypt(
            byte[] encoded,
            String password
    ) throws Exception {

        byte[] all =
                Base64.getDecoder().decode(encoded);

        if (
                all.length < 67
                        || !startsWith(all, MAGIC)
        ) {

            throw new IOException(
                    "Unsupported or malformed .enc file"
            );
        }

        int version = all[8] & 255;
        int kdf = all[9] & 255;
        int cipherId = all[10] & 255;

        if (
                version != VERSION
                        || kdf != KDF_ARGON2ID
                        || cipherId != CIPHER_AES256_GCM
        ) {

            throw new IOException(
                    "Unsupported encryption format"
            );
        }

        int t = readInt(all, 11);
        int mem = readInt(all, 15);
        int p = readInt(all, 19);

        if (
                t < 1
                        || t > 20
                        || mem < 8192
                        || mem > 1024 * 1024
                        || p < 1
                        || p > 32
        ) {

            throw new IOException(
                    "Invalid KDF parameters"
            );
        }

        byte[] salt =
                slice(all, 23, SALT_LEN);

        byte[] nonce =
                slice(all, 39, NONCE_LEN);

        byte[] header =
                slice(all, 0, 51);

        byte[] ct =
                slice(
                        all,
                        51,
                        all.length - 51
                );

        byte[] key =
                derive(
                        password,
                        salt,
                        t,
                        mem,
                        p
                );

        Cipher c =
                Cipher.getInstance(
                        "AES/GCM/NoPadding"
                );

        c.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(128, nonce)
        );

        c.updateAAD(header);

        return c.doFinal(ct);
    }

    private static byte[] derive(
            String password,
            byte[] salt,
            int t,
            int mem,
            int p
    ) {

        Argon2Parameters params =
                new Argon2Parameters.Builder(
                        Argon2Parameters.ARGON2_id
                )
                        .withSalt(salt)
                        .withIterations(t)
                        .withMemoryAsKB(mem)
                        .withParallelism(p)
                        .build();

        Argon2BytesGenerator g =
                new Argon2BytesGenerator();

        g.init(params);

        byte[] out =
                new byte[KEY_LEN];

        g.generateBytes(
                password.toCharArray(),
                out
        );

        return out;
    }

    private static byte[] header(
            int t,
            int mem,
            int p,
            byte[] salt,
            byte[] nonce
    ) throws IOException {

        ByteArrayOutputStream b =
                new ByteArrayOutputStream();

        b.write(MAGIC);
        b.write(VERSION);
        b.write(KDF_ARGON2ID);
        b.write(CIPHER_AES256_GCM);

        writeInt(b, t);
        writeInt(b, mem);
        writeInt(b, p);

        b.write(salt);
        b.write(nonce);

        return b.toByteArray();
    }

    private static void writeInt(
            ByteArrayOutputStream b,
            int x
    ) {

        b.write((x >>> 24) & 255);
        b.write((x >>> 16) & 255);
        b.write((x >>> 8) & 255);
        b.write(x & 255);
    }

    private static int readInt(
            byte[] a,
            int o
    ) {

        return ((a[o] & 255) << 24)
                | ((a[o + 1] & 255) << 16)
                | ((a[o + 2] & 255) << 8)
                | (a[o + 3] & 255);
    }

    private static byte[] slice(
            byte[] a,
            int o,
            int n
    ) {

        byte[] b = new byte[n];

        System.arraycopy(
                a,
                o,
                b,
                0,
                n
        );

        return b;
    }

    private static boolean startsWith(
            byte[] a,
            byte[] b
    ) {

        if (a.length < b.length) {
            return false;
        }

        for (int i = 0; i < b.length; i++) {

            if (a[i] != b[i]) {
                return false;
            }
        }

        return true;
    }

    private byte[] readAll(Uri u)
            throws IOException {

        try (
                InputStream is =
                        getContentResolver()
                                .openInputStream(u);

                ByteArrayOutputStream b =
                        new ByteArrayOutputStream()
        ) {

            if (is == null) {
                throw new IOException(
                        "Cannot read input"
                );
            }

            byte[] x =
                    new byte[1024 * 1024];

            int n;

            while ((n = is.read(x)) != -1) {
                b.write(x, 0, n);
            }

            return b.toByteArray();
        }
    }

    private String displayName(Uri u) {

        String r = null;

        try (
                var c =
                        getContentResolver()
                                .query(
                                        u,
                                        null,
                                        null,
                                        null,
                                        null
                                )
        ) {

            if (
                    c != null
                            && c.moveToFirst()
            ) {

                int i =
                        c.getColumnIndex(
                                OpenableColumns.DISPLAY_NAME
                        );

                if (i >= 0) {
                    r = c.getString(i);
                }
            }

        } catch (Exception ignored) {
        }

        return r != null
                ? r
                : u.toString();
    }

    private void setBusy(boolean b) {

        runOnUiThread(() -> {

            progress.setVisibility(
                    b
                            ? View.VISIBLE
                            : View.GONE
            );

            encrypt.setEnabled(!b);
            decrypt.setEnabled(!b);
        });
    }

    private void fail(String s) {

        runOnUiThread(() -> {

            setBusy(false);

            status.setText(s);

            toast(s);
        });
    }

    private void toast(String s) {

        Toast.makeText(
                this,
                s,
                Toast.LENGTH_LONG
        ).show();
    }
            }

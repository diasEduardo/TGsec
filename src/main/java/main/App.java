/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.lang.NumberFormatException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 *
 * @author Eduardo
 */
public class App {

    private static String menu = "1.Assinar.\n2.Verificar.\n0.Sair";
    private static BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));

    public static void main(String[] args) {
        boolean stop = false;
        Security.addProvider(new BouncyCastleProvider());
        while (!stop) {
            int opt = -1;
            try {
                String input = getFromConsole("Selecione uma opção\n" + menu);
                opt = Integer.parseInt(input);
            } catch (NumberFormatException ex) {
                continue;
            }
            String pkcs = "", doc = "", passw = "", alias = "",doc2 = "";
            KeyStore ks;
            Key key = null;
            Certificate certificate = null;
            int tries = 0;
            byte[] data, data2;
            switch (opt) {
                case 1:
                    pkcs = getFromConsole("Informe o local do arquivo PKCS#12");
                    passw = getFromConsole("Informe a senha");
                    ks = getKeyStore(pkcs, passw);
                    alias = selectAlias(ks);
                    if (alias == "") {
                        System.out.println("erro");
                        break;
                    }
                    key = null;
                    tries = 0;
                    while (key == null && tries < 3) {
                        try {
                            key = ks.getKey(alias, passw.toCharArray());
                        } catch (KeyStoreException ex) {
                        } catch (NoSuchAlgorithmException ex) {
                        } catch (UnrecoverableKeyException ex) {
                        }

                        //Certificate cert = ks.getCertificate(alias);
                        if (key == null) {
                            passw = getFromConsole("Informe a senha para a chave selecionada");
                        }
                    }
                    if (tries >= 3) {
                        break;
                    }

                    doc = getFromConsole("Informe o local do documento");
                    data = null;
                    try {
                        data = Files.readAllBytes(Paths.get(doc));
                    } catch (IOException ex) {
                        Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (data == null) {
                        System.out.println("Documento invalido");
                        break;
                    }
                    byte[] sign = generateSignature((PrivateKey) key, data);
                    File file = new File(doc + ".sig");

                    try {
                        OutputStream os = new FileOutputStream(file);
                        os.write(sign);
                        os.close();
                    } catch (FileNotFoundException ex) {
                    } catch (IOException ex) {
                    }

                    break;
                case 2:
                    pkcs = getFromConsole("Informe o local do arquivo PKCS#12");
//                    System.out.println(pkcs);
                    passw = getFromConsole("Informe a senha");
                    ks = getKeyStore(pkcs, passw);
                    alias = selectAlias(ks);
                    if (alias == "") {
                        System.out.println("Erro: Sem alias");
                        break;
                    }
                    
                    tries = 0;
                    while (certificate == null && tries < 3) {
                        try {
                            certificate = ks.getCertificate(alias);
                        } catch (KeyStoreException ex) {
                            
                        }
                        //Certificate cert = ks.getCertificate(alias);
                    }
                    if (tries >= 3) {
                        break;
                    }
                    
                    doc = getFromConsole("Informe o local do documento aberto");
//                    System.out.println(doc);
                    data = null;
                    try {
                        data = Files.readAllBytes(Paths.get(doc));
                    } catch (IOException ex) {
                        Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (data == null) {
                        System.out.println("Documento invalido");
                        break;
                    }
                    
                    doc2 = getFromConsole("Informe o local do documento cifrado");
//                    System.out.println(doc);
                    data2 = null;
                    try {
                        data2 = Files.readAllBytes(Paths.get(doc2));
                    } catch (IOException ex) {
                        Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (data2 == null) {
                        System.out.println("Documento invalido");
                        break;
                    }
                    
                    boolean verify = verifySignature(certificate, data, data2);
                    if(verify){
                        System.out.println("Assinatura verificada");
                    }
                    else{
                        System.out.println("Assinatura não verificada");
                    }
                    break;
                case 0:
                    stop = true;
                    break;
            }

        }

    }

    public static String getFromConsole(String print) {
        String output = "";
        System.out.println(print);
        try {
            output = reader.readLine();
        } catch (IOException ex) {

        }
        return output;

    }

    public static KeyStore getKeyStore(String path, String passw) {
        KeyStore ks = null;
        FileInputStream fis = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            fis = new FileInputStream(path);
            try {
                ks.load(fis, passw.toCharArray());
            } catch (IOException ex) {

            } catch (NoSuchAlgorithmException ex) {

            } catch (CertificateException ex) {

            }
        } catch (KeyStoreException ex) {

        } catch (FileNotFoundException ex) {

        }
        return ks;
    }

    public static String selectAlias(KeyStore ks) {
        String output = "";
        try {
            System.out.println("\nLista de cert/chaves no arquivo.");
            for (Enumeration en = ks.aliases(); en.hasMoreElements();) {
                String alias = (String) en.nextElement();

                if (ks.isCertificateEntry(alias)) {
                    System.out.println("Certificado ID: " + alias + ", Subject: " + (((X509Certificate) ks.getCertificate(alias)).getSubjectDN()));
                } else if (ks.isKeyEntry(alias)) {
                    System.out.println("chave ID: " + alias + ", Subject: " + (((X509Certificate) ks.getCertificate(alias)).getSubjectDN()));
                }
            }
            output = getFromConsole("Informe o ID:");
            while (!ks.containsAlias(output)) {
                output = getFromConsole("Informe um ID valido:");
            }
        } catch (KeyStoreException ex) {

        }
        return output;
    }

    public static byte[] generateSignature(PrivateKey pKey, byte[] data) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(pKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public static boolean verifySignature(Certificate certificate, byte[] data,byte[] data2) {
        try {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initVerify(certificate);
            signature.update(data);
            return signature.verify(data2);
//            return signature.sign();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(App.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return false;
    }
}

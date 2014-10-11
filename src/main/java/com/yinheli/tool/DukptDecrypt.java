package com.yinheli.tool;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

/**
 * @author yinheli
 */
public class DukptDecrypt {

    private static final String ALG_DES = "DES";
    private static final String ALG_TRIPLE_DES = "DESede";
    private static final String DES_MODE_ECB = "ECB";
    private static final String DES_MODE_CBC = "CBC";
    private static final String DES_NO_PADDING = "NoPadding";

    public static String decrypt(String ksn, String bdk, String data) throws Exception {
        byte[] ksnbytes = Util.hex2byte(ksn);
        byte[] databytes = Util.hex2byte(data);
        byte[] bdkbytes = Util.hex2byte(bdk);
        byte[] ipek = generateIPEK(ksnbytes, bdkbytes);
        byte[] datakey = getDatekey(ksnbytes, ipek);
        return Util.hexString(tdesDec(databytes, datakey));
    }

    private static byte[] getDatekey(byte[] ksn, byte[] ipek) throws Exception {
        byte[] key = Util.trim(ipek, 16);
        byte[] cnt = new byte[3];
        cnt[0] = (byte) (ksn[7] & 0x1F);
        cnt[1] = ksn[8];
        cnt[2] = ksn[9];
        byte[] temp = new byte[8];
        System.arraycopy(ksn, 2, temp, 0, 6);
        temp[5] &= 0xE0;
        int shift = 0x10;
        while (shift > 0) {
            if ((cnt[0] & shift) > 0) {
                temp[5] |= shift;
                key = NRKGP(key, temp);
            }
            shift >>= 1;
        }

        shift = 0x80;
        while (shift > 0) {
            if ((cnt[1] & shift) > 0) {
                temp[6] |= shift;
                key = NRKGP(key, temp);
            }
            shift >>= 1;
        }

        shift = 0x80;
        while (shift > 0) {
            if ((cnt[2] & shift) > 0) {
                temp[7] |= shift;
                key = NRKGP(key, temp);
            }
            shift >>= 1;
        }


        key[5] ^= 0xFF;
        key[13] ^= 0xFF;

        key = tdesEnc(key, key);
        return key;
    }

    private static byte[] NRKGP(byte[] key, byte[] ksn) throws Exception {
        byte[] key_temp = Util.trim(key, 8);
        byte[] temp = new byte[8];
        for (int i = 0; i < 8; i++) {
            temp[i] = (byte) (ksn[i] ^ key[8 + i]);
        }
        byte[] res = tdesEnc(temp, key_temp);
        byte[] key_r = res;
        for (int i = 0; i < 8; i++) {
            key_r[i] ^= key[8 + i];
        }
        key_temp[0] ^= 0xC0;
        key_temp[1] ^= 0xC0;
        key_temp[2] ^= 0xC0;
        key_temp[3] ^= 0xC0;
        key[8] ^= 0xC0;
        key[9] ^= 0xC0;
        key[10] ^= 0xC0;
        key[11] ^= 0xC0;

        temp = new byte[8];
        for (int i = 0; i < 8; i++) {
            temp[i] = (byte) (ksn[i] ^ key[8 + i]);
        }

        res = tdesEnc(temp, key_temp);
        byte[] key_l = res;
        for (int i = 0; i < 8; i++) {
            key[i] = (byte) (key_l[i] ^ key[8 + i]);
        }
        System.arraycopy(key_r, 0, key, 8, 8);
        return key;
    }

    private static byte[] generateIPEK(byte[] ksn, byte[] bdkbytes) throws Exception{
        byte[] temp = Util.trim(ksn, 8);
        byte[] keyTemp = bdkbytes;
        temp[7] = (byte) (0xE0 & temp[7]);
        byte[] temp2 = tdesEnc(temp, keyTemp);
        byte[] result = Util.trim(temp2, 8);
        keyTemp[0] ^= 0xC0;
        keyTemp[1] ^= 0xC0;
        keyTemp[2] ^= 0xC0;
        keyTemp[3] ^= 0xC0;
        keyTemp[8] ^= 0xC0;
        keyTemp[9] ^= 0xC0;
        keyTemp[10] ^= 0xC0;
        keyTemp[11] ^= 0xC0;
        temp2 = tdesEnc(temp, keyTemp);
        result = Util.concat(result, Util.trim(temp2, 8));
        return result;
    }

    private static byte[] tdesEnc(byte[] data, byte[] key) throws Exception {
        Cipher cipher = null;
        if (key.length == 8) {
            cipher = Cipher.getInstance(ALG_DES);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALG_DES));
        } else {
            cipher = Cipher.getInstance(ALG_TRIPLE_DES);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(Util.concat(key, 0, 16, key, 0, 8), ALG_TRIPLE_DES));
        }

        return cipher.doFinal(data);
    }

    private static byte[] tdesDec(byte[] data, byte[] key) throws Exception {
        Cipher cipher = null;
        Key k = null;
        if (key.length == 8) {
            k = new SecretKeySpec(key, ALG_DES);
        } else {
            k = new SecretKeySpec(Util.concat(key, 0, 16, key, 0, 8), ALG_TRIPLE_DES);
        }

        String transformation;
        if (k.getAlgorithm().startsWith(ALG_DES)) {
            StringBuilder sb = new StringBuilder();
            sb.append(k.getAlgorithm()).append("/").append(DES_MODE_CBC).append("/").append(DES_NO_PADDING);
            transformation = sb.toString();
        } else {
            transformation = k.getAlgorithm();
        }

        cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.DECRYPT_MODE, k, new IvParameterSpec(new byte[8]));
        return cipher.doFinal(data);
    }

}

package com.wxmlabs.snippets;

import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.lang.reflect.Field;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 依赖 'org.bouncycastle:bcpkix-jdk15on:1.59+'
 * @author wang_xuanmin@itrus.com.cn
 */
public class VerifyCMSSignedData {
    private BouncyCastleProvider provider = new BouncyCastleProvider();
    private JcaSimpleSignerInfoVerifierBuilder verifierBuilder = new JcaSimpleSignerInfoVerifierBuilder().setProvider(provider);

    /**
     * 使用指定签名原文、签名者证书验证PKCS7格式签名
     *
     * @param origin     签名原文
     * @param pkcs7      PKCS7格式签名
     * @param signerCert 签名者证书
     * @return 验证成功返回true，其他情况返回false
     * @throws CMSException                 无法解析PKCS7签名数据，PKCS7签名数据异常
     * @throws CertificateEncodingException 无法序列化签名者证书，签名者证书数据异常
     */
    boolean verify(byte[] origin, byte[] pkcs7, X509Certificate signerCert) throws CMSException, CertificateEncodingException {
        // 解析并使用指定签名原文
        CMSSignedData s = new CMSSignedData(new CMSProcessableByteArray(origin), pkcs7);
        // 转换为CertificateHolder用于签名信息过滤
        JcaX509CertificateHolder x509CertificateHolder = new JcaX509CertificateHolder(signerCert);

        // 获取所有签名信息
        SignerInformationStore signers = s.getSignerInfos();

        // 找到匹配指定签名者证书的签名信息，进行验证
        AtomicBoolean verified = new AtomicBoolean(false);
        signers.getSigners().stream()
                .filter(signer -> signer.getSID().match(x509CertificateHolder))
                .findFirst()
                .ifPresent(signer -> {
                    if (GMObjectIdentifiers.sm2p256v1.getId().equals(signer.getEncryptionAlgOID())) {
                        try {
                            // 为非标准签名修正OID
                            Field encryptionAlgorithm = signer.getClass().getDeclaredField("encryptionAlgorithm");
                            encryptionAlgorithm.setAccessible(true);
                            encryptionAlgorithm.set(signer, new AlgorithmIdentifier(GMObjectIdentifiers.sm2sign_with_sm3));
                            encryptionAlgorithm.setAccessible(false);
                        } catch (NoSuchFieldException | IllegalAccessException e) {
                            e.printStackTrace();
                        }
                    }
                    try {
                        if (signer.verify(verifierBuilder.build(signerCert))) {
                            verified.set(true);
                        }
                    } catch (OperatorCreationException | CMSException e) {
                        e.printStackTrace();
                    }
                });

        return verified.get();
    }
}

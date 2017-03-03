/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.spark.deploy.rest.kubernetes

import java.io.{File, FileInputStream, FileOutputStream, InputStreamReader}
import java.nio.file.Paths
import java.security.{KeyStore, PrivateKey}
import java.security.cert.X509Certificate
import java.util.UUID

import com.google.common.base.Charsets
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.openssl.{PEMKeyPair, PEMParser}
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter

import org.apache.spark.SparkException
import org.apache.spark.util.Utils

private[spark] object PemsToKeyStoreConverter {

  /**
   * Loads the given key-cert pair into a temporary keystore file. Returns the File pointing
   * to where the keyStore was written to disk.
   */
  def convertPemsToTempKeyStoreFile(
      keyPemFile: File,
      certPemFile: File,
      keyAlias: String,
      keyStorePassword: Option[String],
      keyPassword: Option[String],
      keyStoreType: Option[String]): File = {
    require(keyPemFile.isFile, s"Key pem file provided at ${keyPemFile.getAbsolutePath}" +
      " does not exist or is not a file.")
    require(certPemFile.isFile, s"Cert pem file provided at ${certPemFile.getAbsolutePath}" +
      " does not exist or is not a file.")
    val privateKey = parsePrivateKeyFromPemFile(keyPemFile)
    val certificate = parseCertificateFromPemFile(certPemFile)
    val resolvedKeyStoreType = keyStoreType.getOrElse(KeyStore.getDefaultType)
    val keyStore = KeyStore.getInstance(resolvedKeyStoreType)
    keyStore.load(null, null)
    keyStore.setKeyEntry(
      keyAlias,
      privateKey,
      keyPassword.map(_.toCharArray).orNull,
      Array(certificate))
    val keyStoreOutputPath = Paths.get(s"keystore-${UUID.randomUUID()}.$resolvedKeyStoreType")
    Utils.tryWithResource(new FileOutputStream(keyStoreOutputPath.toFile)) { storeStream =>
      keyStore.store(storeStream, keyStorePassword.map(_.toCharArray).orNull)
    }
    keyStoreOutputPath.toFile
  }

  def convertCertPemToTrustStore(
      certPemFile: File,
      certAlias: String,
      trustStoreType: Option[String]): KeyStore = {
    require(certPemFile.isFile, s"Cert pem file provided at ${certPemFile.getAbsolutePath}" +
      " does not exist or is not a file.")
    val trustStore = KeyStore.getInstance(trustStoreType.getOrElse(KeyStore.getDefaultType))
    trustStore.load(null, null)
    val certificate = parseCertificateFromPemFile(certPemFile)
    trustStore.setCertificateEntry(certAlias, certificate)
    trustStore
  }

  private def parsePrivateKeyFromPemFile(keyPemFile: File): PrivateKey = {
    Utils.tryWithResource(new FileInputStream(keyPemFile)) { keyPemStream =>
      Utils.tryWithResource(new InputStreamReader(keyPemStream, Charsets.UTF_8)) { keyPemReader =>
        Utils.tryWithResource(new PEMParser(keyPemReader)) { keyPemParser =>
          val converter = new JcaPEMKeyConverter
          keyPemParser.readObject() match {
            case privateKey: PrivateKeyInfo =>
              converter.getPrivateKey(privateKey)
            case keyPair: PEMKeyPair =>
              converter.getPrivateKey(keyPair.getPrivateKeyInfo)
            case _ =>
              throw new SparkException(s"Key file provided at ${keyPemFile.getAbsolutePath}" +
                s" is not a key pair or private key PEM file.")
          }
        }
      }
    }
  }

  private def parseCertificateFromPemFile(certPemFile: File): X509Certificate = {
    Utils.tryWithResource(new FileInputStream(certPemFile)) { certPemStream =>
      Utils.tryWithResource(new InputStreamReader(certPemStream, Charsets.UTF_8)) { certPemReader =>
        Utils.tryWithResource(new PEMParser(certPemReader)) { certPemParser =>
          certPemParser.readObject() match {
            case certificate: X509CertificateHolder =>
              val converter = new JcaX509CertificateConverter
              converter.getCertificate(certificate)
            case _ =>
              throw new SparkException(s"Certificate file provided at" +
                s" ${certPemFile.getAbsolutePath} is not a certificate PEM file.")
          }
        }
      }
    }
  }

}

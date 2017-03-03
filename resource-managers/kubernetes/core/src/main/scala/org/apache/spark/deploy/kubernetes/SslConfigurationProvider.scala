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
package org.apache.spark.deploy.kubernetes

import java.io.{File, FileInputStream}
import java.security.{KeyStore, SecureRandom}
import javax.net.ssl.{SSLContext, TrustManagerFactory, X509TrustManager}

import com.google.common.base.Charsets
import com.google.common.io.{BaseEncoding, Files}
import io.fabric8.kubernetes.api.model.{EnvVar, EnvVarBuilder, Secret, Volume, VolumeBuilder, VolumeMount, VolumeMountBuilder}
import io.fabric8.kubernetes.client.KubernetesClient
import scala.collection.JavaConverters._
import scala.collection.mutable

import org.apache.spark.{SecurityManager => SparkSecurityManager, SparkConf, SparkException, SSLOptions}
import org.apache.spark.deploy.kubernetes.config._
import org.apache.spark.deploy.kubernetes.constants._
import org.apache.spark.deploy.rest.kubernetes.{KubernetesFileUtils, PemsToKeyStoreConverter}
import org.apache.spark.util.Utils

private case class SubmissionSSLOptions(
  storeBasedSslOptions: SSLOptions,
  isKeyStoreLocalFile: Boolean,
  keyPem: Option[File],
  isKeyPemLocalFile: Boolean,
  serverCertPem: Option[File],
  isServerCertPemLocalFile: Boolean,
  clientCertPem: Option[File])

private[spark] case class SslConfiguration(
  enabled: Boolean,
  sslPodEnvVars: Array[EnvVar],
  sslPodVolumes: Array[Volume],
  sslPodVolumeMounts: Array[VolumeMount],
  sslSecrets: Array[Secret],
  driverSubmitClientTrustManager: Option[X509TrustManager],
  driverSubmitClientSslContext: SSLContext)

private[spark] class SslConfigurationProvider(
    sparkConf: SparkConf,
    kubernetesAppId: String,
    kubernetesClient: KubernetesClient,
    kubernetesResourceCleaner: KubernetesResourceCleaner) {
  private val SECURE_RANDOM = new SecureRandom()
  private val sslSecretsName = s"$SUBMISSION_SSL_SECRETS_PREFIX-$kubernetesAppId"
  private val sslSecretsDirectory = s"$DRIVER_CONTAINER_SECRETS_BASE_DIR/$kubernetesAppId-ssl"

  def getSslConfiguration(): SslConfiguration = {
    val driverSubmitSslOptions = parseDriverSubmitSslOptions()
    if (driverSubmitSslOptions.storeBasedSslOptions.enabled) {
      val sslSecretsMap = mutable.HashMap[String, String]()
      val storeBasedSslOptions = driverSubmitSslOptions.storeBasedSslOptions
      val sslEnvs = mutable.Buffer[EnvVar]()
      val secrets = mutable.Buffer[Secret]()
      storeBasedSslOptions.keyStore.foreach(store => {
        val onPodKeyStorePath = if (driverSubmitSslOptions.isKeyStoreLocalFile) {
          extractFileContentsToSecret(sslSecretsMap, SUBMISSION_SSL_KEYSTORE_SECRET_NAME, store)
        } else {
          store.getAbsolutePath
        }
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_KEYSTORE_FILE)
          .withValue(onPodKeyStorePath)
          .build()
      })
      storeBasedSslOptions.keyStorePassword.foreach(password => {
        val passwordBase64 = BaseEncoding.base64().encode(password.getBytes(Charsets.UTF_8))
        sslSecretsMap += (SUBMISSION_SSL_KEYSTORE_PASSWORD_SECRET_NAME -> passwordBase64)
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_KEYSTORE_PASSWORD_FILE)
          .withValue(s"$sslSecretsDirectory/$SUBMISSION_SSL_KEYSTORE_PASSWORD_SECRET_NAME")
          .build()
      })
      storeBasedSslOptions.keyPassword.foreach(password => {
        val passwordBase64 = BaseEncoding.base64().encode(password.getBytes(Charsets.UTF_8))
        sslSecretsMap += (SUBMISSION_SSL_KEY_PASSWORD_SECRET_NAME -> passwordBase64)
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_KEYSTORE_KEY_PASSWORD_FILE)
          .withValue(s"$sslSecretsDirectory/$SUBMISSION_SSL_KEY_PASSWORD_SECRET_NAME")
          .build()
      })
      storeBasedSslOptions.keyStoreType.foreach(storeType => {
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_KEYSTORE_TYPE)
          .withValue(storeType)
          .build()
      })
      driverSubmitSslOptions.keyPem.foreach(keyPem => {
        val onPodKeyPem = if (driverSubmitSslOptions.isKeyPemLocalFile) {
          extractFileContentsToSecret(
            sslSecretsMap,
            SUBMISSION_SSL_KEY_PEM_SECRET_NAME,
            keyPem)
        } else {
          keyPem.getAbsolutePath
        }
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_KEY_PEM_FILE)
          .withValue(onPodKeyPem)
          .build()
      })
      driverSubmitSslOptions.serverCertPem.foreach(certPem => {
        val onPodCertPem = if (driverSubmitSslOptions.isServerCertPemLocalFile) {
          extractFileContentsToSecret(
            sslSecretsMap,
            SUBMISSION_SSL_CERT_PEM_SECRET_NAME,
            certPem)
        } else {
          certPem.getAbsolutePath
        }
        sslEnvs += new EnvVarBuilder()
          .withName(ENV_SUBMISSION_CERT_PEM_FILE)
          .withValue(onPodCertPem)
          .build()
      })
      sslEnvs += new EnvVarBuilder()
        .withName(ENV_SUBMISSION_USE_SSL)
        .withValue("true")
        .build()
      val sslVolume = new VolumeBuilder()
        .withName(SUBMISSION_SSL_SECRETS_VOLUME_NAME)
        .withNewSecret()
        .withSecretName(sslSecretsName)
        .endSecret()
        .build()
      val sslVolumeMount = new VolumeMountBuilder()
        .withName(SUBMISSION_SSL_SECRETS_VOLUME_NAME)
        .withReadOnly(true)
        .withMountPath(sslSecretsDirectory)
        .build()
      val sslSecrets = kubernetesClient.secrets().createNew()
        .withNewMetadata()
        .withName(sslSecretsName)
        .endMetadata()
        .withData(sslSecretsMap.asJava)
        .withType("Opaque")
        .done()
      kubernetesResourceCleaner.registerOrUpdateResource(sslSecrets)
      secrets += sslSecrets
      val (driverSubmitClientTrustManager, driverSubmitClientSslContext) =
        buildSslConnectionConfiguration(driverSubmitSslOptions)
      SslConfiguration(
        true,
        sslEnvs.toArray,
        Array(sslVolume),
        Array(sslVolumeMount),
        secrets.toArray,
        driverSubmitClientTrustManager,
        driverSubmitClientSslContext)
    } else {
      SslConfiguration(
        false,
        Array[EnvVar](),
        Array[Volume](),
        Array[VolumeMount](),
        Array[Secret](),
        None,
        SSLContext.getDefault)
    }
  }

  private def extractFileContentsToSecret(
      sslSecretsMap: mutable.HashMap[String, String],
      secretName: String,
      secretFile: File): String = {
    if (!secretFile.isFile) {
      throw new SparkException(s"KeyStore specified at $secretFile is not a file or" +
        s" does not exist.")
    }
    val keyStoreBytes = Files.toByteArray(secretFile)
    val keyStoreBase64 = BaseEncoding.base64().encode(keyStoreBytes)
    sslSecretsMap += (secretName -> keyStoreBase64)
    s"$sslSecretsDirectory/$secretName"
  }

  private def parseDriverSubmitSslOptions(): SubmissionSSLOptions = {
    val maybeKeyStore = sparkConf.get(DRIVER_SUBMIT_SSL_KEYSTORE)
    val maybeTrustStore = sparkConf.get(DRIVER_SUBMIT_SSL_TRUSTSTORE)
    val maybeKeyPem = sparkConf.get(DRIVER_SUBMIT_SSL_KEY_PEM)
    val maybeServerCertPem = sparkConf.get(DRIVER_SUBMIT_SSL_SERVER_CERT_PEM)
    val maybeClientCertPem = sparkConf.get(DRIVER_SUBMIT_SSL_CLIENT_CERT_PEM)
    validatePemsDoNotConflictWithStores(
      maybeKeyStore,
      maybeTrustStore,
      maybeKeyPem,
      maybeServerCertPem,
      maybeClientCertPem)
    val resolvedSparkConf = sparkConf.clone()
    val (isLocalKeyStore, resolvedKeyStore) = resolveLocalFile(maybeKeyStore, "keyStore")
    resolvedKeyStore.foreach {
      resolvedSparkConf.set(DRIVER_SUBMIT_SSL_KEYSTORE, _)
    }
    val (isLocalServerCertPem, resolvedServerCertPem): (Boolean, Option[String]) =
      resolveLocalFile(maybeServerCertPem, "server cert PEM")
    val (isLocalKeyPem, resolvedKeyPem) = resolveLocalFile(maybeKeyPem, "key PEM")
    maybeTrustStore.foreach { trustStore =>
      require(KubernetesFileUtils.isUriLocalFile(trustStore), s"Invalid trustStore URI" +
        s"$trustStore; trustStore URI for submit server must have no scheme, or scheme file://")
      resolvedSparkConf.set(DRIVER_SUBMIT_SSL_TRUSTSTORE, Utils.resolveURI(trustStore).getPath)
    }
    val clientCertPem: Option[String] = maybeClientCertPem.map { clientCert =>
      require(KubernetesFileUtils.isUriLocalFile(clientCert), "Invalid client certificate PEM URI" +
        s" $clientCert: client certificate URI must have no scheme, or scheme file://")
      Utils.resolveURI(clientCert).getPath
    }
    val securityManager = new SparkSecurityManager(resolvedSparkConf)
    val storeBasedSslOptions = securityManager.getSSLOptions(DRIVER_SUBMIT_SSL_NAMESPACE)
    SubmissionSSLOptions(
      storeBasedSslOptions,
      isLocalKeyStore,
      resolvedKeyPem.map(new File(_)),
      isLocalKeyPem,
      resolvedServerCertPem.map(new File(_)),
      isLocalServerCertPem,
      clientCertPem.map(new File(_)))
  }

  private def resolveLocalFile(file: Option[String],
      fileType: String): (Boolean, Option[String]) = {
    file.map { f =>
      require(isValidSslFileScheme(f), s"Invalid $fileType URI $f, $fileType URI" +
        s" for submit server must have scheme file:// or local:// (no scheme defaults to file://")
      val isLocal = KubernetesFileUtils.isUriLocalFile(f)
      (isLocal, Option.apply(Utils.resolveURI(f).getPath))
    }.getOrElse(false, None)
  }

  private def validatePemsDoNotConflictWithStores(
      maybeKeyStore: Option[String],
      maybeTrustStore: Option[String],
      maybeKeyPem: Option[String],
      maybeServerCertPem: Option[String],
      maybeClientCertPem: Option[String]) = {
    // Can only set either pems or keystore/truststore. Specifying one from one category and
    // one from the other category is prohibited.
    val maybeKeyOrServerCertPem = maybeKeyPem.orElse(maybeServerCertPem)
    (maybeKeyStore, maybeKeyOrServerCertPem) match {
      case (Some(_), Some(_)) =>
        throw new SparkException("Cannot specify server PEM files and key store files; must" +
          " specify only one or the other.")
    }
    (maybeKeyPem, maybeServerCertPem) match {
      case (Some(_), None) =>
        throw new SparkException("When specifying the key PEM file, the server certificate PEM" +
          " file must also be provided.")
      case (None, Some(_)) =>
        throw new SparkException("When specifying the server certificate PEM file, the key PEM" +
          " file must also be provided.")
    }
    (maybeTrustStore, maybeClientCertPem) match {
      case (Some(_), Some(_)) =>
        throw new SparkException("Cannot specify client certificate PEM file and trust store" +
          " file; must specify only one or the other.")
    }
  }

  private def isValidSslFileScheme(rawUri: String): Boolean = {
    val resolvedScheme = Option.apply(Utils.resolveURI(rawUri)).getOrElse("file")
    resolvedScheme == "file" || resolvedScheme == "local"
  }

  private def buildSslConnectionConfiguration(driverSubmitSslOptions: SubmissionSSLOptions):
      (Option[X509TrustManager], SSLContext) = {
    val maybeTrustStore = driverSubmitSslOptions.clientCertPem.map { certPem =>
      PemsToKeyStoreConverter.convertCertPemToTrustStore(
        certPem,
        "certificate",
        driverSubmitSslOptions.storeBasedSslOptions.trustStoreType)
    }.orElse(driverSubmitSslOptions.storeBasedSslOptions.trustStore.map { trustStoreFile =>
      if (!trustStoreFile.isFile) {
        throw new SparkException(s"TrustStore file at ${trustStoreFile.getAbsolutePath}" +
          s" does not exist or is not a file.")
      }
      val trustStore = KeyStore.getInstance(
        driverSubmitSslOptions
          .storeBasedSslOptions
          .trustStoreType
          .getOrElse(KeyStore.getDefaultType))
      Utils.tryWithResource(new FileInputStream(trustStoreFile)) { trustStoreStream =>
        driverSubmitSslOptions.storeBasedSslOptions.trustStorePassword match {
          case Some(password) =>
            trustStore.load(trustStoreStream, password.toCharArray)
          case None => trustStore.load(trustStoreStream, null)
        }
      }
      trustStore
    })
    maybeTrustStore.map { trustStore =>
      val trustManagerFactory = TrustManagerFactory.getInstance(
        TrustManagerFactory.getDefaultAlgorithm)
      trustManagerFactory.init(trustStore)
      val trustManagers = trustManagerFactory.getTrustManagers
      val sslContext = SSLContext.getInstance("TLSv1.2")
      sslContext.init(null, trustManagers, SECURE_RANDOM)
      (Option.apply(trustManagers(0).asInstanceOf[X509TrustManager]), sslContext)
    }.getOrElse((Option.empty[X509TrustManager], SSLContext.getDefault))
  }
}
package com.rumblefish.kotlinrumbleapp

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.biometric.BiometricPrompt.PromptInfo
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.web3j.crypto.ECKeyPair
import org.web3j.crypto.Keys
import org.web3j.crypto.Sign
import org.web3j.crypto.Sign.SignatureData
import org.web3j.utils.Numeric
import java.math.BigInteger
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.Security
import java.security.UnrecoverableKeyException
import java.util.concurrent.Executor
import java.util.concurrent.Executors
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec


interface BiometricCallback {
    fun onAuthenticationSuccess(decryptedData: String)
    fun onAuthenticationError(errorCode: Int, errorMessage: String)
    fun onAuthenticationFailed()
}

class MainActivity : AppCompatActivity() {
    private lateinit var editTextInput: EditText
    private lateinit var textViewResult: TextView
    private lateinit var sharedPreferences: SharedPreferences

    private lateinit var keyStore: KeyStore

    private val ANDROID_KEYSTORE_PROVIDER = "AndroidKeyStore"
    private val KEY_ALIAS = "MySharedPreferenceKeyAlias"

    private val KEY_ALIAS_AES = "MyAesKeyAlias"

    private val AES_DEFAULT_TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" +
            KeyProperties.BLOCK_MODE_CBC + "/" +
            KeyProperties.ENCRYPTION_PADDING_PKCS7
    private val DELIMITER = "]"
    private val invalidateEnrollment = true
    private var signatureData: SignatureData? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val initKeyStoreButton = findViewById<Button>(R.id.button1)
        val getEckButton = findViewById<Button>(R.id.button2)
        val signMessageButton = findViewById<Button>(R.id.button4)
        val verifyMessage = findViewById<Button>(R.id.button5)
        val buttonSave = findViewById<Button>(R.id.buttonSave)
        val btnOpenSecondActivity: Button = findViewById(R.id.btnOpenSecondActivity)

        editTextInput = findViewById(R.id.editText)
        textViewResult = findViewById(R.id.textViewResult)
        sharedPreferences = getSharedPreferences(KEY_ALIAS, Context.MODE_PRIVATE)

        keyStore =
            KeyStore.getInstance(ANDROID_KEYSTORE_PROVIDER)
        keyStore.load(null)

        initKeyStoreAndEckPair()

        initKeyStoreButton.setOnClickListener {
            initKeyStoreAndEckPair()
        }

        getEckButton.setOnClickListener {
            deleteKeyStoreAndEckPair()
        }

        buttonSave.setOnClickListener {
            val userInput = editTextInput.text.toString()
            textViewResult.text = "User Input: $userInput"

            hideKeyboard()
        }

        // sign message
        signMessageButton.setOnClickListener {
            val userInput = editTextInput.text.toString()
            val messageBytes = userInput.toByteArray()
            val encryptedPrivateKey = sharedPreferences.getString("eckKey", "")

            if (encryptedPrivateKey != null) {
                getEckPairWithCallback(encryptedPrivateKey, null, object : BiometricCallback {
                    override fun onAuthenticationSuccess(decryptedData: String) {
                        handleEckAuthenticationSuccess(messageBytes, decryptedData) { result ->
                            println("signature data" + result)
                            signatureData = result
                            println("signature data after" )
                            updateVerifyButtonState()
                        }
                    }
                    override fun onAuthenticationError(errorCode: Int, errorMessage: String) {
                        // Handle authentication error here
                    }
                    override fun onAuthenticationFailed() {
                        // Handle authentication failure here
                    }
                })

            }
        }

        // verify message
        verifyMessage.setOnClickListener {
            val userInput = editTextInput.text.toString()
            val hashBytes = calculateHash(userInput)
            val publicKeyHex = getPublicKeyHex(hashBytes)
            val address = getAddressFromPublicKey(publicKeyHex)

            println("Verify address ADDRESS: $address")
        }

        btnOpenSecondActivity.setOnClickListener {
            val intent = Intent(this, SecondActivity::class.java)
            startActivity(intent)
        }
    }

    private fun updateVerifyButtonState() {
        val verifyMessage = findViewById<Button>(R.id.button5)

        if (signatureData == null) {
            verifyMessage.isEnabled = false
            verifyMessage.setTextColor(ContextCompat.getColor(this, R.color.button_text_enabled))

        } else {
            verifyMessage.isEnabled = true
            verifyMessage.setTextColor(ContextCompat.getColor(this, R.color.button_text_disabled))
        }
    }

    private fun calculateHash(message: String): ByteArray {
        val messageBytes = message.toByteArray()
        val digest = KeccakDigest(256)
        val hashBytes = ByteArray(digest.digestSize)

        digest.update(messageBytes, 0, messageBytes.size)
        digest.doFinal(hashBytes, 0)

        return hashBytes
    }



    private fun getPublicKeyHex(hashBytes: ByteArray): String {
        if (signatureData == null) {
            throw IllegalStateException("Signature data is empty")
        }

        val publicKey = Sign.signedMessageHashToKey(hashBytes, signatureData)
        return Numeric.toHexStringNoPrefix(publicKey)
    }

    private fun getAddressFromPublicKey(publicKeyHex: String): String {
        val address = "0x" + Keys.getAddress(publicKeyHex)
        return address
    }

    private fun handleEckAuthenticationSuccess(messageBytes: ByteArray, decryptedData: String, callback: (SignatureData) -> Unit) {
        val privateKeyBigInt = BigInteger(decryptedData, 16)
        val ecKeyPair = ECKeyPair.create(privateKeyBigInt)
        val address = Keys.getAddress(ecKeyPair)
        println("Sign message address: $address")

        val digest = KeccakDigest(256)
        val hashBytes = ByteArray(digest.digestSize)
        digest.update(messageBytes, 0, messageBytes.size)
        digest.doFinal(hashBytes, 0)

        CoroutineScope(Dispatchers.IO).launch {
            val signatureData = Sign.signMessage(hashBytes, ecKeyPair, false)

            withContext(Dispatchers.Main) {
                callback(signatureData)
            }
        }
    }

    private fun initKeyStoreAndEckPair() {
        setupBouncyCastle()
        updateVerifyButtonState()

        CoroutineScope(Dispatchers.Main).launch {
            initKeyStore()
//            prepareKey()
            createAndSaveEckPair()
        }
    }

    private fun deleteKeyStoreAndEckPair() {
        val editor = sharedPreferences.edit()
        editor.remove("eckKey")
        editor.apply()

        keyStore.deleteEntry(KEY_ALIAS_AES)
        keyStore.deleteEntry(KEY_ALIAS)
    }

    private suspend fun initKeyStore(): Any? = withContext(Dispatchers.IO) {
        try {
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

                    val keyGenerator: KeyGenerator = KeyGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_AES,
                        ANDROID_KEYSTORE_PROVIDER
                    )

                    val builder = KeyGenParameterSpec.Builder(
                        KEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    ).apply {
                        setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        setKeySize(256)
                        setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        setUserAuthenticationRequired(true)
                    }

//                    val builder: KeyGenParameterSpec.Builder =
//                        KeyGenParameterSpec.Builder(
//                            KEY_ALIAS,
//                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
//                        )
//                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
//                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
//                            .setRandomizedEncryptionRequired(false)
////                            .setUserAuthenticationRequired(true)

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                        // Check if biometric enrollment invalidation is supported
                        val keyguardManager = this@MainActivity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
                        builder.setInvalidatedByBiometricEnrollment(keyguardManager.isDeviceSecure)
                    }

                    keyGenerator.init(builder.build())
                    keyGenerator.generateKey()
                } else {
                    Log.d("TODO - IMPLEMENT ANOTHER WAY", "Another way to create private key needed")
                }
            } else {
                val secretKey = keyStore?.getKey(KEY_ALIAS_AES, null)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private suspend fun prepareKey(): Any? = withContext(Dispatchers.IO) {
        if (keyStore.containsAlias(KEY_ALIAS_AES)) {
            return@withContext null // Key is already prepared, return early
        }
        val keyGenerator: KeyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE_PROVIDER
        )

        val builder = KeyGenParameterSpec.Builder(
            KEY_ALIAS_AES,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        ).apply {
            setBlockModes(KeyProperties.BLOCK_MODE_CBC)
            setKeySize(256)
            setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
            setUserAuthenticationRequired(true)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                builder.setInvalidatedByBiometricEnrollment(invalidateEnrollment)
            } catch (e: Exception) {
                Log.d(
                    "setInvalidatedByBiometricEnrollment",
                    "Error setting setInvalidatedByBiometricEnrollment: ${e.message}"
                )
            }
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
        println("Prepared keys")

        return@withContext null
    }

    private fun createAndSaveEckPair() {
        try {
            val savedValue = sharedPreferences.getString("eckKey", "")

            if (savedValue.isNullOrEmpty()) {
                val ecKeyPair: ECKeyPair = Keys.createEcKeyPair()
                val privateKey: BigInteger = ecKeyPair.getPrivateKey()
                val privateKeyHex = privateKey.toString(16)
                val address = Keys.getAddress(ecKeyPair)

                println("createAndSaveEckPair address: $address")

                saveToSharedPreferences(privateKeyHex, null)
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun saveToSharedPreferences(value: String, cipher: Cipher?) {
        val secretKey = keyStore?.getKey(KEY_ALIAS, null)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                if (cipher == null) {
                    var updatedCipher: Cipher
                    updatedCipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    updatedCipher.init(Cipher.ENCRYPT_MODE, secretKey)

                            class PutExtraWithAESCallback : BiometricPrompt.AuthenticationCallback() {
                                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                    println("onAuthenticationSucceeded from callback")

                                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                        saveToSharedPreferences(value, result.cryptoObject?.cipher)
                                    }
                                }

                                override fun onAuthenticationError(
                                    errorCode: Int,
                                    errString: CharSequence
                                ) {
                                    println("AUTH ERROR")
                                }

                                override fun onAuthenticationFailed() {
                                    println("AUTH FAILED")
                                }
                            }
                            println("BEFORE SHOW MODAL")
                            showDialog(BiometricPrompt.CryptoObject(updatedCipher), PutExtraWithAESCallback())

                    return
                }

                val encryptedBytes = cipher!!.doFinal(value.toByteArray())
                val base64IV = Base64.encodeToString(cipher.getIV(), Base64.DEFAULT)
                val base64Cipher = Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
                val result = base64IV + DELIMITER + base64Cipher

                val editor = sharedPreferences.edit()
                editor.putString("eckKey", result)
                editor.apply()


            } catch (e: InvalidKeyException) {

            } catch (e: UnrecoverableKeyException) {

            } catch (e: IllegalBlockSizeException) {

            } catch (e: SecurityException) {

            } catch (e: java.lang.Exception) {

            }
        } else {
            Log.d("BIOMETRICS NOT SUPPORTED", "Biometrics not supported")
        }
    }

    private fun getEckPairWithCallback(encrypted: String, cipher: Cipher?, callback: BiometricCallback){
        val secretKey = keyStore?.getKey(KEY_ALIAS, null)

        val inputs: Array<String> =
            encrypted.split(DELIMITER)
                .dropLastWhile { it.isEmpty() }
                .toTypedArray()

        if (inputs.size < 2) {
            Log.d("@getEckPair2", inputs.toString())
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                val iv = Base64.decode(inputs[0], Base64.DEFAULT)
                val cipherBytes = Base64.decode(inputs[1], Base64.DEFAULT)

                if (cipher == null) {
                    var updatedCipher: Cipher
                    updatedCipher = Cipher.getInstance(AES_DEFAULT_TRANSFORMATION)
                    updatedCipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))

                    class DecryptWithAesCallback : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            println("onAuthenticationSucceeded from callback eckpair")

                            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                                getEckPairWithCallback(encrypted, result.cryptoObject?.cipher, callback)
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
//                                    pm.reject(String.valueOf(errorCode), errString.toString());
                            println("AUTH ERROR")
                        }

                        override fun onAuthenticationFailed() {
                            println("AUTH FAILED")
                        }
                    }
                    println("BEFORE SHOW MODAL")
                    showDialog(BiometricPrompt.CryptoObject(updatedCipher), DecryptWithAesCallback())
                }

                val decryptedBytes = String(cipher?.doFinal(cipherBytes) ?: byteArrayOf())
                val privateKeyBigInt = BigInteger(decryptedBytes, 16)
                val ecKeyPair = ECKeyPair.create(privateKeyBigInt)
                val address = Keys.getAddress(ecKeyPair)
                println("getEckPair Address: $address")

                callback.onAuthenticationSuccess(decryptedBytes)

            } catch (e: InvalidKeyException) {

            } catch (e: UnrecoverableKeyException) {

            } catch (e: IllegalBlockSizeException) {

            } catch (e: SecurityException) {

            } catch (e: java.lang.Exception) {

            }
        } else {
            Log.d("BIOMETRICS NOT SUPPORTED", "Biometrics not supported")
        }
    }

    private fun showDialog(
        cryptoObject: BiometricPrompt.CryptoObject,
        callback: BiometricPrompt.AuthenticationCallback
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val executor: Executor = Executors.newSingleThreadExecutor()
            val biometricPrompt = BiometricPrompt(this, executor, callback)

            val promptInfo = PromptInfo.Builder()
                .setTitle("Unlock with your biometric")
                .setDescription("Place your finger on the fingerprint sensor to unlock.")
                .setNegativeButtonText("Cancel")
                .build()

            biometricPrompt.authenticate(promptInfo, cryptoObject)
        }
    }

    private fun setupBouncyCastle() {
        val provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) ?:
        // Web3j will set up the provider lazily when it's first used.
            return
        if (provider.javaClass == BouncyCastleProvider::class.java) {
            // BC with same package name, shouldn't happen in real life.
            return
        }
        // Android registers its own BC provider. As it might be outdated and might not include
        // all needed ciphers, we substitute it with a known BC bundled in the app.
        // Android's BC has its package rewritten to "com.android.org.bouncycastle" and because
        // of that it's possible to have another BC implementation loaded in VM.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)
    }

    private fun hideKeyboard() {
        val imm = getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager
        imm.hideSoftInputFromWindow(currentFocus?.windowToken, 0)
    }
}
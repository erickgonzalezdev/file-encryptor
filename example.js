import Encrypt from './index.js'

const test = async () => {
  // Instantiate Library
  const encrypt = new Encrypt()
  // Generate KeyPair
  const keyPair = encrypt.generateKeyPair()
  console.log('keyPair', keyPair)
  // Data to encrypt
  const fileToEncrypt = 'Hello World'
  // Encryt data using public key
  console.log(`To Encrypt : ${fileToEncrypt}`)
  const encrypted = await encrypt.encrypt(fileToEncrypt, keyPair.publicKey)
  // Decrypt data using private key
  const decryptedData = await encrypt.decrypt(encrypted, keyPair.privateKey)
  const decrypted = encrypt.unit8ToString(decryptedData)
  console.log(`Decrypted : ${decrypted}`)

  if (decrypted === fileToEncrypt) {
    console.log('Successfull!')
  } else {
    console.log('Error!')
  }
}

test()

import * as ECIES from 'eciesjs'
import { Base64 } from 'js-base64'

/**
 *   --- Encrypt process ---
 *  -generate random ECIES KeyPairs
 *  -Generate GCM key and IV
 *  -Encrypt file using GCM Key
 *  -Using A-publicKey to encrypt the GCM key
 *  -merge IV +  EncryptedFileData + Encrypted GCM key  in a single file
 *
 *   --- Decrypt process ---
 *
 * - Retrieve file with the IV +  EncryptedFileData + Encrypted GCM key
 * - Separate data
 * - Decrypt GCM key  with A-Private key
 * - Decrypt Encrypted file data.
 */

class WebEncrypt {
  constructor () {
    this.encrypt = this.encrypt.bind(this)
    this.generateGCMKey = this.generateGCMKey.bind(this)
    this.generateKeyPair = this.generateKeyPair.bind(this)
    this.generateIV = this.generateIV.bind(this)
    this.getFileHash = this.getFileHash.bind(this)
  }

  async encryptAESGCM (data, keyHex) {
    try {
      const hexIv = this.generateIV()
      const iv = this.hexToBuffer(hexIv)
      const key = await this.importKey(keyHex)

      const enc = new TextEncoder()
      const dataBuffer = typeof data === 'string' ? enc.encode(data) : data

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        dataBuffer
      )

      return {
        encryptedData: encrypted,
        iv: hexIv
      }
    } catch (error) {
      console.error('encryptAESGCM error:', error)
      throw error
    }
  }

  async decryptAESGCM (encryptedData, keyHex, iv) {
    try {
      const enc = new TextEncoder()
      const dataBuffer = typeof encryptedData === 'string' ? enc.encode(encryptedData) : encryptedData

      const key = await this.importKey(keyHex)

      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        dataBuffer
      )

      return new Uint8Array(decrypted)
    } catch (error) {
      console.error('decryptAESGCM error:', error)
      throw error
    }
  }

  async encrypt (data, publicKey) {
    try {
      if (!data) throw new Error('data to encrypt is required')
      if (!publicKey) throw new Error('publicKey is required')

      const gcmKey = this.generateGCMKey()
      const { iv, encryptedData } = await this.encryptAESGCM(data, gcmKey)
      const unitIv = this.hexToBuffer(iv)
      const encodeGCMKey = new TextEncoder().encode(gcmKey)
      const encryptedGCM = ECIES.encrypt(publicKey, encodeGCMKey)

      const mergedData = new Uint8Array(unitIv.byteLength + encryptedData.byteLength + encryptedGCM.byteLength)
      mergedData.set(unitIv, 0)
      mergedData.set(new Uint8Array(encryptedData), unitIv.byteLength)
      mergedData.set(new Uint8Array(encryptedGCM), unitIv.byteLength + encryptedData.byteLength)

      const base64String = Base64.fromUint8Array(mergedData)
      return base64String
    } catch (error) {
      console.error('encrypt error:', error)
      throw error
    }
  }

  async decrypt (inData, privateKey) {
    try {
      if (!inData) throw new Error('data to decrypt is required')
      if (!privateKey) throw new Error('privateKey is required')

      const data = Base64.toUint8Array(inData)
      const ivLength = 12
      const gcmEncryptedLength = 161

      const iv = data.slice(0, ivLength)
      const _encryptedGCM = data.slice(data.length - gcmEncryptedLength)
      const encryptedData = data.slice(ivLength, data.length - gcmEncryptedLength)

      const decryptedGCM = ECIES.decrypt(privateKey, _encryptedGCM)
      const decodedGCM = new TextDecoder().decode(decryptedGCM)

      const decryptedData = await this.decryptAESGCM(encryptedData, decodedGCM, iv)
      return decryptedData
    } catch (error) {
      console.error('decrypt error:', error)
      throw error
    }
  }

  generateKeyPair () {
    const keyp = new ECIES.PrivateKey()
    const privateKeyHex = this.bufferToHex(keyp.secret)
    const publicKeyHex = this.bufferToHex(keyp.publicKey.toBytes())

    return {
      privateKey: privateKeyHex,
      publicKey: publicKeyHex
    }
  }

  generateGCMKey () {
    const key = crypto.getRandomValues(new Uint8Array(32))
    return this.bufferToHex(key)
  }

  generateIV () {
    const key = crypto.getRandomValues(new Uint8Array(12))
    return this.bufferToHex(key)
  }

  async getFileHash (data) {
    try {
      const buffer = typeof data === 'string'
        ? new TextEncoder().encode(data)
        : data

      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
      return this.bufferToHex(new Uint8Array(hashBuffer))
    } catch (error) {
      console.error('getFileHash error:', error)
      throw error
    }
  }

  async importKey (keyHex) {
    try {
      const keyBuffer = this.hexToBuffer(keyHex)
      return await crypto.subtle.importKey(
        'raw',
        keyBuffer,
        { name: 'AES-GCM' },
        false,
        ['encrypt', 'decrypt']
      )
    } catch (error) {
      console.error('importKey error:', error)
      throw error
    }
  }

  hexToBuffer (hex) {
    const bytes = new Uint8Array(hex.length / 2)
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
    }
    return bytes
  }

  bufferToHex (buffer) {
    return [...buffer].map(b => b.toString(16).padStart(2, '0')).join('')
  }

  unit8ToString (unit8) {
    return new TextDecoder().decode(unit8)
  }
}

export default WebEncrypt

import * as ECIES from 'eciesjs'
import { Base64 } from 'js-base64'

/**
 *   --- Encrypt process ---
 *  -generate random ECIES KeyPairs
 *  -Generate GCM key and IV
 *  -Encrypt file using GCM Key
 *  -Using A-publicKey to encrypt the GCM key
 *  -merge header + IV +   Encrypted GCM key + EncryptedFileData in a single file
 *
 *   --- Decrypt process ---
 *
 * - Retrieve file with the header + IV  + Encrypted GCM key +EncryptedFileData
 * - Separate data
 * - Decrypt GCM key  with A-Private key
 * - Decrypt Encrypted file data.
 */

class Encrypt {
  constructor () {
    this.decoder = new TextDecoder()
    this.encoder = new TextEncoder()
    this.headerStr = 'HybridEncrypt1.0.0'
    this.header = Base64.toBase64(this.headerStr)
    this.encrypt = this.encrypt.bind(this)
    this.decrypt = this.decrypt.bind(this)
    this.generateGCMKey = this.generateGCMKey.bind(this)
    this.generateKeyPair = this.generateKeyPair.bind(this)
    this.generateIV = this.generateIV.bind(this)
    this.getFileHash = this.getFileHash.bind(this)
    this.isEncryptedFile = this.isEncryptedFile.bind(this)
    this.encryptStream = this.encryptReadableStream.bind(this)
    this.decryptStream = this.decryptReadableStream.bind(this)
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

      const header = new TextEncoder().encode(this.header)
      const gcmKey = this.generateGCMKey()
      const { iv, encryptedData } = await this.encryptAESGCM(data, gcmKey)
      const unitIv = this.hexToBuffer(iv)
      const encodeGCMKey = new TextEncoder().encode(gcmKey)
      const encryptedGCM = ECIES.encrypt(publicKey, encodeGCMKey)

      const mergedData = new Uint8Array(header.byteLength + unitIv.byteLength + encryptedData.byteLength + encryptedGCM.byteLength)

      mergedData.set(header, 0)
      mergedData.set(unitIv, header.byteLength)
      mergedData.set(new Uint8Array(encryptedData), header.byteLength + unitIv.byteLength)
      mergedData.set(new Uint8Array(encryptedGCM), header.byteLength + unitIv.byteLength + encryptedData.byteLength)

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

      const headerLength = this.header.length
      const ivLength = 12
      const gcmEncryptedLength = 161 // ECIES encrypted 32-byte key

      const iv = data.slice(headerLength, headerLength + ivLength)
      const _encryptedGCM = data.slice(data.length - gcmEncryptedLength)
      const encryptedData = data.slice(headerLength + ivLength, data.length - gcmEncryptedLength)

      const decryptedGCM = ECIES.decrypt(privateKey, _encryptedGCM)
      const decodedGCM = this.decoder.decode(decryptedGCM)

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
    return this.decoder.decode(unit8)
  }

  async isEncryptedFile (input) {
    try {
      const expectedHeader = this.header
      const expectedHeaderLength = expectedHeader.length

      // Caso: Blob o File (navegador)
      if (input instanceof Blob) {
        const headerBuf = await input.slice(0, expectedHeaderLength).arrayBuffer()
        const headerStr = this.decoder.decode(headerBuf)
        return headerStr === expectedHeader
      }

      // Caso: Uint8Array o Buffer (Node.js o browser)
      if (input instanceof Uint8Array || (typeof Buffer !== 'undefined' && Buffer.isBuffer(input))) {
        const headerBytes = input.slice(0, expectedHeaderLength)
        const headerStr = this.decoder.decode(headerBytes)
        return headerStr === expectedHeader
      }

      // Caso: Base64 string
      if (typeof input === 'string') {
        const bytes = Base64.toUint8Array(input)
        const headerBytes = bytes.slice(0, expectedHeaderLength)
        const headerStr = this.decoder.decode(headerBytes)
        return headerStr === expectedHeader
      }

      // Tipo no reconocido
      return false
    } catch (error) {
      console.error('isEncryptedFile error:', error)
      return false
    }
  }

  async encryptReadableStream (stream, publicKey) {
    try {
      let buffer = new Uint8Array(0)
      const chunkSize = 64 * 1024 // 64 KB por chunk
      const gcmKey = this.generateGCMKey()
      if (!stream?.getReader) {
        throw new Error('Readable Stream is required!')
      }
      const reader = await stream.getReader()
      const encryptedChunks = []
      const header = this.encoder.encode(this.header)
      while (true) {
        const { done, value } = await reader.read()
        if (done) {
          if (buffer.length > 0) {
            const { encryptedData, iv } = await this.encryptAESGCM(buffer, gcmKey)
            const unitIv = this.hexToBuffer(iv)
            const combinedChunk = new Uint8Array(unitIv.byteLength + encryptedData.byteLength)
            combinedChunk.set(unitIv, 0)
            combinedChunk.set(new Uint8Array(encryptedData), unitIv.byteLength)

            encryptedChunks.push(combinedChunk)
          }
          break
        }
        if (value) {
          const temp = new Uint8Array(buffer.byteLength + value.byteLength)
          temp.set(buffer)
          temp.set(value, buffer.byteLength)
          buffer = temp

          while (buffer.length >= chunkSize) {
            const chunk = buffer.slice(0, chunkSize)
            buffer = buffer.slice(chunkSize)

            const { encryptedData, iv } = await this.encryptAESGCM(chunk, gcmKey)
            const unitIv = this.hexToBuffer(iv)

            const combinedChunk = new Uint8Array(unitIv.byteLength + encryptedData.byteLength)
            combinedChunk.set(unitIv, 0)
            combinedChunk.set(new Uint8Array(encryptedData), unitIv.byteLength)

            encryptedChunks.push(combinedChunk)
          }
        }
      }
      // concat all chunks
      const totalLength = encryptedChunks.reduce((sum, c) => sum + c.byteLength, 0)
      const allEncryptedData = new Uint8Array(totalLength)
      let pos = 0
      for (const chunk of encryptedChunks) {
        allEncryptedData.set(chunk, pos)
        pos += chunk.byteLength
      }

      const encodeGCMKey = this.encoder.encode(gcmKey)
      const encryptedGCM = await ECIES.encrypt(publicKey, encodeGCMKey)

      const mergedData = new Uint8Array(header.byteLength + encryptedGCM.byteLength + allEncryptedData.byteLength)
      mergedData.set(header, 0)
      mergedData.set(encryptedGCM, header.byteLength)
      mergedData.set(allEncryptedData, header.byteLength + encryptedGCM.byteLength)
      return mergedData
    } catch (error) {
      console.error('encryptReadableStream error:', error)
      throw error
    }
  }

  async decryptReadableStream (stream, privateKey) {
    try {
      let buffer = new Uint8Array(0)
      if (!stream?.getReader) {
        throw new Error('Readable Stream is required!')
      }
      const reader = await stream.getReader()

      const headerLength = this.header.length
      const ivLength = 12
      const gcmEncryptedLength = 161 // ECIES encrypted 32-byte key
      const chunkEncryptedLength = 64 * 1024 + 16 // 65552 bytes
      let decryptedGCM = null
      const decryptedChunks = []

      let headerFromData = ''
      let encryptedGcmFromData = ''

      while (true) {
        const { done, value } = await reader.read()
        let metadataLength = 0
        if (done) {
          if (buffer.length > 0) {
            const iv = buffer.slice(0, ivLength)
            const encryptedData = buffer.slice(ivLength)

            const decryptedChunk = await this.decryptAESGCM(encryptedData, decryptedGCM, iv)
            decryptedChunks.push(decryptedChunk)
          }
          break
        }
        if (value && value.length >= headerLength + gcmEncryptedLength && !headerFromData) {
          headerFromData = value.slice(0, headerLength)
          // const headerDecode = this.decoder.decode(headerFromData)
          encryptedGcmFromData = value.slice(headerLength, headerLength + gcmEncryptedLength)

          decryptedGCM = await ECIES.decrypt(privateKey, encryptedGcmFromData)
          decryptedGCM = this.decoder.decode(decryptedGCM)
          metadataLength = headerLength + gcmEncryptedLength
        }

        if (value) {
          const temp = new Uint8Array((buffer.byteLength + value.byteLength) - metadataLength)

          const remaining = value.slice(metadataLength, value.byteLength)
          temp.set(buffer)
          temp.set(remaining, buffer.byteLength)
          buffer = temp

          while (buffer.length >= chunkEncryptedLength + ivLength) {
            const chunk = buffer.slice(0, chunkEncryptedLength + ivLength)
            buffer = buffer.slice(chunkEncryptedLength + ivLength)
            const iv = chunk.slice(0, ivLength)
            const encryptedData = chunk.slice(ivLength)

            const decryptedChunk = await this.decryptAESGCM(encryptedData, decryptedGCM, iv)
            decryptedChunks.push(decryptedChunk)
          }
        }
      }
      const totalLength = decryptedChunks.reduce((sum, c) => sum + c.byteLength, 0)
      const allDecryptedData = new Uint8Array(totalLength)
      let pos = 0
      for (const chunk of decryptedChunks) {
        allDecryptedData.set(chunk, pos)
        pos += chunk.byteLength
      }

      return allDecryptedData
    } catch (error) {
      console.error('decryptReadableStream error:', error)
      throw error
    }
  }
}

export default Encrypt

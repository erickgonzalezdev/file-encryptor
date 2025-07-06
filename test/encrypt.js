import { assert } from 'chai'
import sinon from 'sinon'
import { describe, it } from 'mocha'

import Encrypt from '../src/encrypt.js'

describe('#Encrypt', () => {
  let uut
  let sandbox
  const encryptKey = '093e75663f48b3bcde3655804ad1d63e18b530afb179a7c3f6b3ce43ebae0c00' //  encrypt.generateKey()
  let encryptedData
  before(async () => {
    uut = new Encrypt()
  })

  beforeEach(() => {
    sandbox = sinon.createSandbox()
  })

  afterEach(() => {
    sandbox.restore()
  })

  after(async () => {
  })

  describe('#encrypt', () => {
    it('should encrypt', async () => {
      const data = Buffer.from('test data')
      const res = await uut.encrypt(data, encryptKey)

      assert.exists(res)
      encryptedData = res
    })
    it('should handle error', async () => {
      try {
        const data = Buffer.from('test data')
        await uut.encrypt(data, 'wron key format')
        assert.fail('should not be here')
      } catch (error) {
        assert.include(error.message, 'Invalid key')
      }
    })
  })
  describe('#decrypt', () => {
    it('should decrypt', async () => {
      const res = await uut.decrypt(encryptedData, encryptKey)
      assert.exists(res)
      assert.equal(res.toString(), 'test data')
    })
    it('should handle error', async () => {
      try {
        const data = Buffer.from('test data')
        await uut.decrypt(data, 'wron key format')
        assert.fail('should not be here')
      } catch (error) {
        assert.include(error.message, 'Invalid key')
      }
    })
  })
  describe('#getFileHash', () => {
    it('should get hash 256', async () => {
      const data = Buffer.from('test data')
      const res = await uut.getFileHash(data)
      assert.exists(res)
      assert.isString(res)
    })
    it('should handle error', async () => {
      try {
        await uut.getFileHash()
        assert.fail('should not be here')
      } catch (error) {
        assert.include(error.message, 'The first argument must be of type string')
      }
    })
  })
  describe('#generateKey', () => {
    it('should generateKey', async () => {
      const res = uut.generateKey()
      assert.isString(res)
      assert.equal(res.length, 64)
    })
  })

  describe('#generateIV', () => {
    it('should generateIV', async () => {
      const res = uut.generateIV()
      assert.isString(res)
      assert.equal(res.length, 24)
    })
  })
})

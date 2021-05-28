const axios = require('axios');
const crypto = require('crypto');
const x509 = require('@ghaiklor/x509');

const authHash = require('./authhash.js');

const CERT_BEGIN = '-----BEGIN CERTIFICATE-----\n';
const CERT_END = '\n-----END CERTIFICATE-----';

function timeout(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class Session {
  constructor(config, request, id, verificationCode) {
    this.config = config;
    this._request = request;
    this.id = id;
    this.verificationCode = verificationCode;
  }

  pollStatus() {
    return new Promise((resolve, reject) => {
      const pull = () => {
        axios({
          method: 'GET',
          responseType: 'json',
          validateStatus: (status) => status === 200,
          url: this.config.host + '/session/'+ this.id + '?timeoutMs=10000'
        }).then(response => {
          let body = response.data;
          if (typeof body !== 'object') {
            return reject(new Error('Invalid response'));
          }
          if (body.state && body.state !== 'COMPLETE') { // not completed yet, retry
            return setTimeout(pull.bind(this), 100);
          } else {
            if (!body.result) {
              return reject(new Error('Invalid response (empty result)'));
            } else if (body.result.endResult !== 'OK') {
              return reject(new Error(body.result.endResult));
            } else { // result.endResult = "OK"
              // verify signature:
              const verifier = crypto.createVerify(body.signature.algorithm);
              verifier.update(this._request.hash.raw);
              const cert = CERT_BEGIN + body.cert.value + CERT_END;
              if (!verifier.verify(cert, body.signature.value, 'base64')) {
                return reject(new Error('Invalid signature (verify failed)'));
              }
              // check if cert is active and not expired:
              const parsedCert = x509.parseCert(cert);
              const date = new Date();
              if (parsedCert.notBefore > date) {
                return reject(new Error('Certificate is not active yet'));
              } else if (parsedCert.notAfter < date) { 
                return reject(new Error('Certificate has expired'));
              } else {
                return resolve({ data: x509.getSubject(cert), result: body.result });
              }
            }
          }
        }).catch(err => reject(err))
      };
      pull();
    });
  }

  async getResponse(rejectNotOK) {
    let response;
    try {
      response = await axios(
        Object.assign(
          {
            method: 'GET',
            responseType: 'json',
            validateStatus: (status) => status === 200,
            url: this.config.host + '/session/' + this.id + '?timeoutMs=10000',
          },
          this.config.http || {}
        )
      );
    } catch (err) {
      response = err.response;
    }

    const body = response && response.data;
    if (typeof body !== 'object') {
      throw new Error(`Invalid response: ${body}`);
    } else if (!body.state && !body.result) {
      throw new Error(`Invalid response: ${JSON.stringify(body)}`);
    } else if (body.state && body.state !== 'COMPLETE') {
      // not completed yet, retry after 100ms
      await timeout(100);
      await this.getResponse(rejectNotOK);
    } else {
      if (body.result.endResult !== 'OK') {
        if (rejectNotOK) {
          throw new Error(`Invalid result: ${body.result.endResult}`);
        } else {
          return {
            result: body.result.endResult,
            data: body,
          };
        }
      } else {
        // result.endResult = "OK"
        // verify signature:
        const verifier = crypto.createVerify(body.signature.algorithm);
        verifier.update(this._request.hash.raw);
        const cert = CERT_BEGIN + body.cert.value + CERT_END;
        if (!verifier.verify(cert, body.signature.value, 'base64')) {
          throw new Error('Invalid signature (verify failed)');
        }
        // check if cert is active and not expired:
        const parsedCert = x509.parseCert(cert);
        const date = new Date();
        if (parsedCert.notBefore > date) {
          throw new Error('Certificate is not active yet');
        } else if (parsedCert.notAfter < date) {
          throw new Error('Certificate has expired');
        } else {
          return {
            result: body.result.endResult,
            subject: x509.getSubject(cert),
            data: body,
          };
        }
      }
    }
  }
}

class Authentication {
  constructor(config, country, idNumber) {
    this.config = config;
    this.request = {
      idNumber: idNumber,
      country: country.toUpperCase(),
    };
  }

  authenticate(displayText) {
    return new Promise((resolve, reject) => {
      authHash.generateRandomHash().then(hash => {
        this.request.hash = hash;
        axios({
          method: 'post',
          url: this.config.host + '/authentication/pno/' + this.request.country + '/' + this.request.idNumber,
          responseType: 'json',
          validateStatus: (status) => status === 200,
          data: Object.assign({
            hash: hash.digest,
            hashType: 'SHA512',
            displayText: (typeof displayText === 'string' ? displayText : undefined)
          }, this.config.requestParams)
        }).then(response => {
          let body = response.data;
          if (typeof body !== 'object' || !body.sessionID) {
            return reject(new Error('Invalid response'));
          }
          resolve(new Session(this.config, this.request, body.sessionID, authHash.calculateVerificationCode(hash.digest)));
        }).catch(err => reject(err));
      });
    });
  }
}

class SmartID {
  constructor(config) {
    if (!config.host || !config.requestParams)
      throw new TypeError('Invalid configuration');

    this.config = config;
  }

  async authenticate(country, idNumber, displayText) {
    if (!country || !idNumber)
      throw new TypeError('Missing mandatory parameters');

    const auth = new Authentication(this.config, country, idNumber);
    const response = await auth.authenticate(displayText);
    return response;
  }
}

module.exports = SmartID;

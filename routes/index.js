var express = require('express');
var CryptoService = require('../services/crypto.service');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  let val = 'encryptionWorks!';
  const encrypted$ = CryptoService.encrypt(val);

  const decrypt$ = encrypted$.switchMap(cipher => CryptoService.decrypt(cipher));
  decrypt$.subscribe((plain) => {
      console.log(plain);
      res.render('index', { title: 'Nodejs encryption PoC' , val: plain});
  });
});

module.exports = router;

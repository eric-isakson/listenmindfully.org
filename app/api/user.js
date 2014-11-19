var express = require('express')
    , router = express.Router();

router.get('/:id?', function(req, res) {
    // TODO add verification checks and respond with a list of users the current user is authorized to see
    res.json(req.isAuthenticated() ? req.user : {});
});

module.exports = router;

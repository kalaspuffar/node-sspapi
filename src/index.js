const Blowfish = require('egoroof-blowfish');
const https = require('https')
const express = require('express');
const qr = require('qr-image');  
const sodium = require('libsodium');
const url = require('url');

const port = 15134;
const site_url = 'https://192.168.6.2:' + port;
const blowfishSecret = 'supersecret';
var bfCounter = 1;

const CURRENT_ID_MATCH = 1;
const PREVIOUS_ID_MATCH = 2;
const IP_MATCHED = 4;
const ACCOUNT_DISABLED = 8;
const FUNCTION_NOT_SUPPORTED = 16;
const TRANSIENT_ERROR = 32;
const COMMAND_FAILED = 64;
const CLIENT_FAILURE = 128;
const BAD_ID_ASSOCIATION = 256;

const app = express();
const cors = require('cors')
const bf = new Blowfish(blowfishSecret, Blowfish.MODE.ECB, Blowfish.PADDING.NULL);

app.use(cors());

const transientSessions = [];

app.get('/nut.sqrl', createNut);
app.get('/png.sqrl', createImage);

app.get('/cli.sqrl', handleClientCalls);

app.get('/pag.sqrl', handlePageRedirect);
app.get('/cps.sqrl', handleCPSRedirect);

app.get('/add.sqrl', associateAccount);
app.get('/rem.sqrl', disassociateAccount);
app.get('/lst.sqrl', listAccountInformation);
app.get('/inv.sqrl', registerInvitation);


https.createServer({
    key: fs.readFileSync('server.key'),
    cert: fs.readFileSync('server.cert')    
}, app).listen(port, () => {
    console.log(`SSPAPI listening on port ${port}!`)
});

//app.listen(port, () => console.log(`SSPAPI listening on port ${port}!`))

function base64url_encode(str) {
    let buff = new Buffer(str);
    let base64 = buff.toString('base64');
    return base64.replace(/\//gi, "_").replace(/\+/gi, "-").replace(/=/gi, "");
}

function base64url_decode(str) {
    let data = str.replace(/_/gi, "/").replace(/-/gi, "+");
    let buff = new Buffer(data, 'base64');
    return buff.toString('utf-8');
}

function createNut(req, res) {
    let data = 'domain.com';
    let xLen = Object.keys(req.query)[0];

    if(isNaN(xLen)) {
        res.send(
            'nut=' + generateNut() + 
            '&can=' + base64url_encode(data)
        );
    } else {
        res.send(
            'x=' + xLen + 
            '&nut=' + base64url_encode(bfEncoded) + 
            '&can=' + base64url_encode(data)
        );
    }
}

function createImage(req, res) {
    let nut = Object.keys(req.query)[0];

    var urlObj = url.parse(site_url);
    var domain = urlObj.hostname;
    if(urlObj.port) {
        domain +=  ':' + urlObj.port;
    }

    let code = qr.image('sqrl://' + domain + '/cli.sqrl?nut=' + nut , { type: 'png' });  
    code.pipe(res);  
}

function generateNut() {
    bfEncoded = bf.encode('' + bfCounter);
    bfCounter++;
    return base64url_encode(bfEncoded)
}

/**
 * Return with information to the server about the error that occured.
 */
function exitWithErrorCode(res, retVal, clientProvidedSession = false, transientSession = false) {
    response = [];
    response.push("ver=1");
    response.push("tif=" + dechex(retVal));
    response.push("sin=0");

    if(transientSession) {
        pathLenParam = getPathLength();

        nut = generateNut();
        transientSessions[nut] = transientSession;

        adminPostPath = parse_url(admin_url('admin-post.php'), PHP_URL_PATH);
        response.push("nut=" + $nut);
        response.push("qry=" + adminPostPath + "?action=sqrl_auth&nut=" + nut + pathLenParam);
    }

    if(clientProvidedSession) {
        response.push("url=" + getServerUrlWithoutPath() + adminPostPath + '?action=sqrl_logout&message=' + MESSAGE_ERROR);
    }

    console.log("Failed response: ", response);

    content = base64url_encode(response.join("\r\n") + "\r\n");
    header('Content-Type: application/x-www-form-urlencoded');
    header('Content-Length: ' + content.length);
    res.send(content);
    exit();
}

/**
 * Base64 is an encoding to encode any set of bytes using only 64 characters. Usually this entails
 * the characters a-z, A-Z, 0-9, /, + and =. The characters /, + and = are not valid characters to be
 * used in URLs so Base64URL uses the _ instead of / and - instead of +. We also don't use any padding with
 * = because that character does not work in URLs.
 *
 * The function below checks that the string is Base64URL encoded and if not it will report the string to
 * the error log and die. This means that if any incorrect data is sent the execution will halt here and not
 * continue.
 */
function onlyAllowBase64URL(res, str) {
    if(!preg_match('/^[a-zA-Z0-9_-]*$/', str)) {
        console.log("Incorrect input " + str);
        exitWithErrorCode(res, TRANSIENT_ERROR);
    }
}

function getClientIP(request) {
    var ip = request.headers['x-forwarded-for'] ||
        request.connection.remoteAddress ||
        request.socket.remoteAddress ||
        request.connection.socket.remoteAddress;
    ip = ip.split(',')[0];
    ip = ip.split(':').slice(-1); //in case the ip returned in a format: "::ffff:146.xxx.xxx.xxx"
    return ip;
}

function accountPresent(idk) {
    return false;
}

function getServerUnlockKey(client) {
    console.log("getServerUnlockKey");
}

function accountDisabled(client) {
    console.log("accountDisabled");
}

function getUserId() {
    console.log("getUserId");
}

function getVerifyUnlockKey(client) {
    console.log("getVerifyUnlockKey");
}

function enableUser(user) {
    console.log("enableUser");
}

function disableUser(user) {
    console.log("disableUser");    
}

function disAssociateUser(user) {
    console.log("disAssociateUser");
}

function dechex(retVal) {
    return retVal.toString(16);
}

function getPathLength() {
    var urlObj = url.parse(site_url)

    if(urlObj.pathname.length > 0) {
        return '&x=' + urlObj.pathname.length;
    }
    return "";
}

/**
 * This function returns the server url without path
 */
function getServerUrlWithoutPath() {
    var urlObj = url.parse(site_url)

    var url = urlObj.scheme;
    url += '://';
    url += urlObj.hostname;
    if (urlObj.port) {
        url += ':';
        url += urlObj.port;
    }
    return url;
}

function handleClientCalls(req, res) {

    // Fix to handle google bot trying to connect to the callback URL.
    // Looking for required post parameters and exit if missing.
    if(!req.query.client || !req.query.server || !req.query.ids) {
        console.log("Missing required parameter");
        exitWithErrorCode(res, CLIENT_FAILURE);
    }

    // Validate data
    // If the string is not Base64URL encoded, die here and don't process code below.
    onlyAllowBase64URL(res, req.query.client);
    onlyAllowBase64URL(res, req.query.server);
    onlyAllowBase64URL(res, req.query.ids);
    onlyAllowBase64URL(res, req.query.pids);
    onlyAllowBase64URL(res, req.query.urs);

    /**
     * Reset return value used as the tif (Transaction Information Flags)
     */
    retVal = 0;

    /**
     * Split the client variables into an array so we can use them later.
     */
    clientStr = base64url_decode(req.query.client).split("\r\n");
    client = [];
    for(let i=0; i<clientStr.length; i++) {
        var valuePair = clientStr[i].split("=");
        client[valuePair[0]] = valuePair[1];
    }

    /**
     * Check the user call that we have a valid signature for the current authentication.
     */
    var result = sodium.crypto_sign_verify_detached (
        base64url_decode(req.query.ids),
        req.query.client + req.query.server,
        base64url_decode(client["idk"])
    );
    if(!result) {
        console.log("Incorrect signature");
        exitWithErrorCode(res, CLIENT_FAILURE);
    }

    /**
     * Check the user call that we have a valid pewvious if available signature for
     * the current authentication.
     */
    if(client["pidk"]) {
        result = sodium.crypto_sign_verify_detached(
            base64url_decode(req.query.pids),
            req.query.client + req.query.server,
            base64url_decode(client["pidk"])
        );
        if(!result) {
            console.log("Incorrect previous signature");
            exitWithErrorCode(res, CLIENT_FAILURE);
        }
    }

    /**
     * Prepare the server values. If the previous value from the client is only a single value that means
     * the client only have seen the URL from the server and we should fetch the query values from the call.
     *
     * Otherwise we handle the server string with properties that are line separated.
     */
    serverStr = base64url_decode(req.query.server).split("\r\n");
    if(count(serverStr) == 1) {
        var urlSplit = serverStr.split("&");
        for(var i=0; i<urlSplit.length; i++) {
            var valuePair = urlSplit[i].split("=");
            server[valuePair[0]] = valuePair[1];
        }
    } else {
        server = [];
        for(var i=0; i<serverStr.length; i++) {
            var valuePair = serverStr[i].split("=");
            server[valuePair[0]] = valuePair[1];
        }
    }

    /**
     * Split the option array with all the SQRL options. Valid values are
     *
     * suk = Request for Server unlock key
     * cps = Client Provided Session is available
     * noiptest = Server don't need to check the IP address of the client (remote device login)
     * sqrlonly = Client requests the server to only allow SQRL logins, all other authentication should be
     * 			  disabled.
     * hardlock = Client request all "out of band" changes to the account. Like security questions to
     * 			  retrieve the account when password is lost.
     */
    options = [];
    optionSplit = client["opt"].split("~");
    for(var i=0; i<optionSplit.length; i++) {
        $options[optionSplit[i]] = true;
    }

    clientProvidedSession = options["cps"];

    /**
     * Fetch the current transient session where we keep all session information.
     */
    transientSession = transientSessions[server["nut"]];
    delete(transientSessions[server["nut"]]);

    /**
     * Check if the users IP have changed since last time we logged in. Only required when CPS is used.
     */
    if (transientSession) {
        console.log("Missing transient session");
        exitWithErrorCode(res, TRANSIENT_ERROR, clientProvidedSession);
    }

    if (options["noiptest"]) {
        if (transientSession["ip"] == getClientIP(req)) {
            retVal += IP_MATCHED;
        }
    }

    /**
     * Get the a new random nut
     */
    nut = generateRandomString();

    /**
     * Prepare response.
     *
     * Set version number for the call, new nut for the session and a path with query that the next client
     * call should use in order to contact the server.
     */
    pathLenParam = getPathLength();

    associatedExistingUser = false;
    response = [];
    response.push("ver=1");

    if(client['cmd'] == 'query') {
        /**
         * Query the system for the current user status.
         */
        if(accountPresent(client['idk'])) {
            retVal += CURRENT_ID_MATCH;

            /**
             * If the client requests a Server Unlock Key then add that to the response.
             */
            if(options["suk"]) {
                response.pus("suk=" + getServerUnlockKey(client));
            }
        }

        if(accountPresent(client['pidk'])) {
            retVal += PREVIOUS_ID_MATCH;
        }
        if(accountDisabled(client)) {
            retVal += ACCOUNT_DISABLED;
        }

    } else if(client['cmd'] == 'ident') {
        /**
         * Identify with the system either creating a new user or authorizing login with a user
         * already in the system.
         */
        if(!accountPresent(client['idk'])) {
            /*
                * Fetch the current user from the transient session store and remove it as we only keep
                * it for the current session.
                */
            user = transientSession["user"];

            /*
             * We need to check if the user is in the transient session before we lookup the user from
             * a previous identity. This association is only on already logged in users on the profile page.
             */
            if(user) {
                associatedExistingUser = true;
            }

            /*
             * Check if we have a hit on a previous account so we need to update the current identity
             * to our new identity identifier.
             */
            if(!user && accountPresent(client['pidk'])) {
                user = getUserId(client['pidk']);
            }

            /*
                * Check if we should associate an old user or create a new one. Checking if registring users
                * are allowed on the current installation.
                */
            if(user) {
                associateUser(user, client);
            } else {
                if (!get_option( 'users_can_register' )) {
                    transientSession["err"] = MESSAGE_REGISTRATION_NOT_ALLOWED;
                } else {
                    transientSession["client"] = client;
                    transientSession["cmd"] = COMMAND_REGISTER;
                }
            }
        }

        /**
         * Check if user is present in the system after eventual creation of the user.
         */
        if(accountPresent(client['idk'])) {
            retVal += CURRENT_ID_MATCH;

            transientSession["cmd"] = COMMAND_LOGIN;
            transientSession["user"] = getUserId(client['idk']);
        }

        /**
         * If Client Provided Session is enabled we need to respond with links for the client to follow in order
         * to securely login.
         */
        if(clientProvidedSession) {
            response.push("url=" + getServerUrlWithoutPath() + adminPostPath +
                "?action=sqrl_login&nut=" + nut +
                (associatedExistingUser ? "&existingUser=1" : ""));
        } else {
            /**
             * Add session data signaling to the reload.js script that a login has been successfully transacted.
             */
            transientSessions[transientSession["session"]] = transientSession;
        }

    } else if(client['cmd'] == 'disable') {
        /*
         * Fetch user to disable.
         */
        user = getUserId(client['idk']);
        if (!user) {
            user = getUserId(client['pidk']);
        }

        if (!user) {
            console.log("User is missing, can't disable");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }

        disableUser(user);

        retVal += CURRENT_ID_MATCH + ACCOUNT_DISABLED;

        transientSession["cmd"] = COMMAND_DISABLE;
        transientSession["user"] = user;

        response.push("suk=" + getServerUnlockKey(client));

        /**
         * If Client Provided Session is enabled we need to respond with links for the client to follow in order
         * to securely login.
         */
        if(clientProvidedSession) {
            response.push("url=" + getServerUrlWithoutPath() + adminPostPath + '?action=sqrl_logout&message=' + MESSAGE_DISABLED);
        } else {
            /**
             * Add session data signaling to the reload.js script that a login has been successfully transacted.
             */
            transientSessions[transientSession["session"]] = transientSession;
        }
    } else if($client['cmd'] == 'enable') {
        /*
         * Fetch user to be enabled.
         */
        user = getUserId(client['idk']);
        if (!user) {
            user = getUserId(client['pidk']);
        }
        if (!user) {
            console.log("User is missing, can't be enable");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }
        if (!accountDisabled(client)) {
            console.log("User is not disabled, can't be enable");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }

        result = sodium.crypto_sign_verify_detached(
            base64url_decode(req.query.urs),
            req.query.client + req.query.server,
            base64url_decode(getVerifyUnlockKey(client))
        );
        if(!$result) {
            console.log("Incorrect Unlock Request signature");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }

        enableUser(user);

        retVal += CURRENT_ID_MATCH;

        transientSession["cmd"] = COMMAND_ENABLE;
        transientSession["user"] = user;

        /**
         * If Client Provided Session is enabled we need to respond with links for the client to follow in order
         * to securely login.
         */
        if(clientProvidedSession) {
            response.push("url=" + getServerUrlWithoutPath() + adminPostPath +
                "?action=sqrl_login&nut=" + nut);
        } else {
            /**
             * Add session data signaling to the reload.js script that a login has been successfully transacted.
             */
            transientSessions[transientSession["session"]] = transientSession;
        }
    } else if($client['cmd'] == 'remove') {
        /*
         * Fetch user to be removed.
         */
        user = getUserId(client['idk']);
        if (!user) {
            user = getUserId(client['pidk']);
        }
        if (!user) {
            console.log("User is missing, can't be removed");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }

        result = sodium.crypto_sign_verify_detached(
            base64url_decode(req.query.urs),
            req.query.client + req.query.server,
            base64url_decode(getVerifyUnlockKey(client))
        );
        if(!result) {
            console.log("Incorrect Unlock Request signature");
            exitWithErrorCode(res, COMMAND_FAILED, clientProvidedSession, transientSession);
        }

        transientSession["cmd"] = COMMAND_REMOVE;

        disAssociateUser(user);
        /**
         * If Client Provided Session is enabled we need to respond with links for the client to follow in order
         * to securely login.
         */
        if(clientProvidedSession) {
            profilePath = parse_url(admin_url('profile.php'), PHP_URL_PATH);
            if(transientSession["user"]) {
                response.push("url=" + getServerUrlWithoutPath() + profilePath);
            } else {
                response.push("url=" + getServerUrlWithoutPath() + adminPostPath + '?action=sqrl_logout&message=' + MESSAGE_REMOVED);
            }
        } else {
            transientSessions[transientSession["session"]] = transientSession;
        }
    } else {
        /**
         * If we have an unknown command, Not implemented yet we should print the client request and die.
         */
        console.log(client);
        exitWithErrorCode(res, FUNCTION_NOT_SUPPORTED, clientProvidedSession, transientSession);
    }

    /**
     * Set the extra options for users preferences.
     */
    updateOptions(client, options);

    /**
     * Set the status condition code for this call.
     */
    response.push("tif=" + dechex(retVal));
    response.push("sin=0");

    /*
     * Prepare the return values and set the transient session
     * where we keep all the session information.
     */
    response.push("nut=" + nut);
    response.push("qry=" + adminPostPath + "?action=sqrl_auth&nut=" + nut + pathLenParam);
    
    transientSessions[nut] = transientSession;    

    /**
     * Display the result as an base64url encoded string.
     */
    content = base64url_encode(response.join("\r\n") + "\r\n");
    header('Content-Type: application/x-www-form-urlencoded');
    header('Content-Length: ' + content.length);
    res.send(content);
}

function handlePageRedirect(req, res) {
    console.log('handlePageRedirect', req.query);
    res.status(404).send('Not found');
}

function handleCPSRedirect(req, res) {
    console.log('handleCPSRedirect', req.query);
    res.status(404).send('Not found');
}

function associateAccount(req, res) {
    console.log('associateAccount', req.query);
    res.status(404).send('Not found');
}

function disassociateAccount(req, res) {
    console.log('disassociateAccount', req.query);
    res.status(404).send('Not found');
}

function listAccountInformation(req, res) {
    console.log('listAccountInformation', req.query);
    res.status(404).send('Not found');
}

function registerInvitation(req, res) {
    console.log('registerInvitation', req.query);
    res.status(404).send('Not found');
}


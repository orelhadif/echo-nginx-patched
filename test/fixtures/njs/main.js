import crypto from 'crypto';

function hello(r) {
    r.return(200, `hello from njs ${njs.version} method=${r.method} uri=${r.uri}\n`);
}

// Proves the large body arrived intact: length + sha256 of what nginx received.
function echo(r) {
    const body = r.requestBuffer || Buffer.alloc(0);
    const digest = crypto.createHash('sha256').update(body).digest('hex');
    r.return(200, `len=${body.length} sha256=${digest}\n`);
}

export default { hello, echo };

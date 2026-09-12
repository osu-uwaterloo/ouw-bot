const MAX_MESSAGE_SIZE = 256 * 1024;

export default {
    async email(message, env) {
        const verificationAddress = env.VERIFICATION_ADDRESS.toLowerCase();
        if (message.to.toLowerCase() !== verificationAddress) {
            message.setReject('Unknown verification address');
            return;
        }
        if (message.rawSize > MAX_MESSAGE_SIZE) {
            message.setReject('Verification email is too large');
            return;
        }

        // Buffer once so fetch has a fixed-length body. The bot performs the
        // actual MIME parsing and DKIM verification over these original bytes.
        const rawMessage = await new Response(message.raw).arrayBuffer();
        const response = await fetch(env.BOT_INBOUND_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${env.WEBHOOK_SECRET}`,
                'Content-Type': 'message/rfc822',
                'X-OUW-Envelope-From': message.from,
                'X-OUW-Envelope-To': message.to,
            },
            body: rawMessage,
        });

        // A 5xx is temporary and should be retried by Email Routing. A 4xx is
        // a permanent rejection (bad signature, recipient, or message shape).
        if (response.status >= 500) {
            throw new Error(`Verification service returned ${response.status}`);
        }
        if (!response.ok) {
            message.setReject('Email could not be used for verification');
        }
    },
};

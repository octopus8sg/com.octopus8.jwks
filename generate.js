import { generateKeyPair, exportJWK } from 'jose';
import { writeFileSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

// Polyfill for __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Function to generate and save the JWKS
async function generateJWKSet() {
  // Generate an EC key pair for signing (ES256)
  const { publicKey: sigPublicKey, privateKey: sigPrivateKey } = await generateKeyPair('ES256');
  const sigPublicJWK = await exportJWK(sigPublicKey);
  const sigPrivateJWK = await exportJWK(sigPrivateKey);

  // Add properties for the signature key
  sigPublicJWK.alg = 'ES256';
  sigPublicJWK.use = 'sig';
  sigPublicJWK.kid = 'my-sig-key';
  sigPrivateJWK.alg = 'ES256';
  sigPrivateJWK.use = 'sig';
  sigPrivateJWK.kid = 'my-sig-key';

  // Generate an EC key pair for encryption (ECDH-ES+A256KW)
  const { publicKey: encPublicKey, privateKey: encPrivateKey } = await generateKeyPair('ECDH-ES+A256KW');
  const encPublicJWK = await exportJWK(encPublicKey);
  const encPrivateJWK = await exportJWK(encPrivateKey);

  // Add properties for the encryption key
  encPublicJWK.alg = 'ECDH-ES+A256KW';
  encPublicJWK.use = 'enc';
  encPublicJWK.kid = 'my-enc-key';
  encPrivateJWK.alg = 'ECDH-ES+A256KW';
  encPrivateJWK.use = 'enc';
  encPrivateJWK.kid = 'my-enc-key';

  // Construct the JWKS with both public and private keys
  const publicJWKS = { keys: [sigPublicJWK, encPublicJWK] };
  const privateJWKS = {
    keys: [
      { ...sigPublicJWK, d: sigPrivateJWK.d },
      { ...encPublicJWK, d: encPrivateJWK.d },
    ],
  };

  // Save the JWKS to JSON files
  saveToJsonFile('public-jwks.json', publicJWKS);
  saveToJsonFile('private-jwks.json', privateJWKS);

  console.log('JWKS files generated successfully.');
}

// Helper function to save JSON data to a file
function saveToJsonFile(fileName, data) {
  const filePath = path.join(__dirname, fileName);
  writeFileSync(filePath, JSON.stringify(data, null, 2));
  console.log(`Saved ${fileName} to ${filePath}`);
}

// Run the function
generateJWKSet();

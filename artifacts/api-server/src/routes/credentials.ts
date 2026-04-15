import { Router, type IRouter } from "express";

const router: IRouter = Router();

router.get("/vci/issuer-metadata", (req, res) => {
  const baseUrl = `${req.protocol}://${req.get("host")}/api`;
  res.json({
    credential_issuer: "https://gimelid.com",
    credential_endpoint: `${baseUrl}/vci/credential`,
    token_endpoint: `${baseUrl}/vci/token`,
    credential_configurations_supported: {
      "GAuthPoACredential": {
        format: "jwt_vc_json",
        scope: "gauth_poa",
        cryptographic_binding_methods_supported: ["did:key", "did:web"],
        credential_signing_alg_values_supported: ["ES256", "RS256"],
        credential_definition: {
          type: ["VerifiableCredential", "GAuthPoACredential"],
        },
      },
      "GAuthDelegationCredential": {
        format: "jwt_vc_json",
        scope: "gauth_delegation",
        cryptographic_binding_methods_supported: ["did:key"],
        credential_signing_alg_values_supported: ["ES256"],
        credential_definition: {
          type: ["VerifiableCredential", "GAuthDelegationCredential"],
        },
      },
    },
  });
});

export default router;

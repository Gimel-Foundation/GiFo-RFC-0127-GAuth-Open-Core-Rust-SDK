import { useVciIssuerMetadata } from "@workspace/api-client-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Key, ShieldCheck, CheckCircle2, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function CredentialsPage() {
  const { data: issuerMetadata, isLoading } = useVciIssuerMetadata();

  const metadata = issuerMetadata as any;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold tracking-tight uppercase font-mono text-foreground mb-1">
          Credentials
        </h1>
        <p className="text-muted-foreground font-mono text-sm">
          OpenID4VCI Issue and VP Verification endpoints.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4 bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <Key className="h-4 w-4" /> VCI Issuer Configuration
            </CardTitle>
          </CardHeader>
          <CardContent className="p-4">
            {isLoading ? (
              <div className="text-center font-mono text-sm text-muted-foreground p-4">
                Loading issuer metadata...
              </div>
            ) : metadata ? (
              <div className="space-y-4 font-mono text-sm">
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground uppercase">Issuer Identifier</div>
                  <div className="text-primary font-bold break-all">
                    {metadata.credential_issuer}
                  </div>
                </div>
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground uppercase">Credential Endpoint</div>
                  <div className="text-foreground break-all">{metadata.credential_endpoint}</div>
                </div>
                <div className="space-y-1">
                  <div className="text-xs text-muted-foreground uppercase">Token Endpoint</div>
                  <div className="text-foreground break-all">{metadata.token_endpoint}</div>
                </div>
                <div className="pt-4 border-t border-border">
                  <div className="text-xs text-muted-foreground uppercase mb-2">
                    Supported Formats
                  </div>
                  {Object.keys(metadata.credential_configurations_supported || {}).map(
                    (key: string) => (
                      <div key={key} className="flex items-center gap-2 mb-1 text-xs">
                        <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                        <span>{key}</span>
                      </div>
                    )
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center font-mono text-sm text-muted-foreground p-4">
                Metadata unavailable.
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card border-border rounded-none shadow-none">
          <CardHeader className="border-b border-border pb-4 bg-secondary/10">
            <CardTitle className="font-mono uppercase text-sm flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" /> Operations
            </CardTitle>
            <CardDescription className="font-mono text-xs">
              Manual interaction tools for OpenID4VCI and VP.
            </CardDescription>
          </CardHeader>
          <CardContent className="p-6 flex flex-col items-center justify-center text-center space-y-6">
            <div className="w-full max-w-sm space-y-4">
              <div className="border border-border p-4 bg-background">
                <Lock className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <h3 className="font-mono text-sm font-bold uppercase text-primary mb-1">
                  Issue Credential Offer
                </h3>
                <p className="font-mono text-xs text-muted-foreground mb-4">
                  Generate a pre-authorized code for a mandate VC.
                </p>
                <Button
                  variant="outline"
                  className="w-full rounded-none font-mono text-xs uppercase"
                  disabled
                >
                  Coming Soon
                </Button>
              </div>
              <div className="border border-border p-4 bg-background">
                <ShieldCheck className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <h3 className="font-mono text-sm font-bold uppercase text-primary mb-1">
                  Verify Presentation
                </h3>
                <p className="font-mono text-xs text-muted-foreground mb-4">
                  Submit a Verifiable Presentation for validation.
                </p>
                <Button
                  variant="outline"
                  className="w-full rounded-none font-mono text-xs uppercase"
                  disabled
                >
                  Coming Soon
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

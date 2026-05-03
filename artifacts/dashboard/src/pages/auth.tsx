import { useState } from "react";
import { useAuth } from "@/lib/auth";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Shield } from "lucide-react";

export default function AuthPage() {
  const [password, setPassword] = useState("");
  const [error, setError] = useState(false);
  const { login } = useAuth();
  const [, navigate] = useLocation();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (login(password)) {
      navigate("/");
    } else {
      setError(true);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm bg-card border-border rounded-none shadow-none">
        <CardHeader className="text-center border-b border-border pb-6">
          <Shield className="h-10 w-10 text-primary mx-auto mb-3" />
          <CardTitle className="font-mono uppercase text-lg tracking-wider">
            GAuth Dashboard
          </CardTitle>
          <p className="font-mono text-xs text-muted-foreground mt-1">
            Open Core v0.92 — Rust SDK
          </p>
        </CardHeader>
        <CardContent className="pt-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <Input
                type="password"
                placeholder="Enter access code (or leave empty)"
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  setError(false);
                }}
                className="rounded-none font-mono text-sm"
              />
              {error && (
                <p className="text-destructive font-mono text-xs mt-1">
                  Invalid access code
                </p>
              )}
            </div>
            <Button
              type="submit"
              className="w-full rounded-none font-mono uppercase text-xs"
            >
              Authenticate
            </Button>
            <p className="font-mono text-[10px] text-muted-foreground text-center">
              Leave password empty for demo access
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}

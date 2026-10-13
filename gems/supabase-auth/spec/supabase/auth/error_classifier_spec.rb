# frozen_string_literal: true

RSpec.describe "Auth Error Classifier" do
  Response = Struct.new(:status, :body)

  def classify(status, body)
    Supabase::Auth::ErrorClassifier.classify_response(Response.new(status, body))
  end

  describe ".classify_response" do
    it "returns nil for a success response" do
      expect(classify(200, '{"ok":true}')).to be_nil
    end

    it "classifies a JSON object error with its message and code" do
      err = classify(400, '{"code":"invalid_credentials","msg":"Invalid login credentials"}')
      expect(err).to be_a(Supabase::Auth::AuthApiError)
      expect(err.message).to eq("Invalid login credentials")
      expect(err.code).to eq("invalid_credentials")
    end

    it "does not raise when the body is a JSON array" do
      err = classify(422, '[{"message":"whatever"}]')
      expect(err).to be_a(Supabase::Auth::AuthUnknownError)
      expect(err.message).to include("message")
    end

    it "does not raise when the body is a bare JSON string" do
      err = classify(400, '"oops"')
      expect(err).to be_a(Supabase::Auth::AuthUnknownError)
      expect(err.message).to eq('"oops"')
    end

    it "keeps a usable message when the object has no known message key" do
      err = classify(400, '{"unexpected":"shape"}')
      expect(err).to be_a(Supabase::Auth::AuthApiError)
      expect(err.message).to include("unexpected")
      expect(err.message).not_to be_empty
    end

    it "classifies a non-JSON body as AuthUnknownError" do
      err = classify(400, "<html>nope</html>")
      expect(err).to be_a(Supabase::Auth::AuthUnknownError)
      expect(err.message).to eq("<html>nope</html>")
    end

    it "classifies weak_password responses with their reasons" do
      body = '{"code":"weak_password","msg":"Password is too weak","weak_password":{"reasons":["length"]}}'
      err = classify(422, body)
      expect(err).to be_a(Supabase::Auth::AuthWeakPasswordError)
      expect(err.reasons).to eq(["length"])
    end

    it "treats 502, 503 and 504 as retryable" do
      [502, 503, 504].each do |status|
        expect(classify(status, "upstream unavailable")).to be_a(Supabase::Auth::AuthRetryableFetchError)
      end
    end
  end
end

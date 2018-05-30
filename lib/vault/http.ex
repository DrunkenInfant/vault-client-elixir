defmodule Vault.Http do
  def get(%Vault.Conn{} = vault, url) do
    HTTPoison.get(build_url(vault, url), headers(vault), hackney: hackney_options(vault))
    |> parse_response()
  end

  def list(%Vault.Conn{} = vault, url) do
    HTTPoison.request(:list, build_url(vault, url), "", headers(vault), hackney: hackney_options(vault))
    |> parse_response()
  end

  def post(%Vault.Conn{} = vault, url, body) do
    HTTPoison.post(
      build_url(vault, url),
      Poison.encode!(body),
      headers(vault),
      hackney: hackney_options(vault)
    )
    |> parse_response()
  end

  def put(%Vault.Conn{} = vault, url, body) do
    HTTPoison.put(
      build_url(vault, url),
      Poison.encode!(body),
      headers(vault),
      hackney: hackney_options(vault)
    )
    |> parse_response()
  end

  def build_url(%{host: host}, url), do: "#{host}/v1#{url}"

  defp parse_response({:ok, %HTTPoison.Response{status_code: 204}}), do: {:ok, :no_content}

  defp parse_response(
         {:ok, %HTTPoison.Response{body: body, status_code: status, headers: headers}}
       ) do
    {parse_status_code(status), parse_response_body(headers, body)}
  end

  defp parse_response({:error, %HTTPoison.Error{reason: {:options, {:cacertfile, _}}}}) do
    {:error, "Bad ssl certificate"}
  end

  defp parse_response({:error, error}) do
    {:error, error}
  end

  defp parse_status_code(status) when status >= 200 and status < 300, do: :ok
  defp parse_status_code(404), do: :not_found
  defp parse_status_code(_), do: :not_ok

  defp parse_response_body(headers, body) do
    Enum.find(
      headers,
      {"Content-Type", "text/plain"},
      fn {key, _} -> key == "Content-Type" end
    )
    |> decode_response_body(body)
  end

  defp decode_response_body({"Content-Type", "application/json" <> _}, body) do
    Poison.decode!(body)
  end

  defp decode_response_body(_, body), do: body

  defp headers(%{token: token}), do: [{"X-Vault-Token", token}]

  defp hackney_options(vault) do
    [ssl_options: ssl_options(vault)]
  end

  defp ssl_options(%{ca_fingerprint: nil}), do: [verify: :verify_peer]

  defp ssl_options(%{ca_fingerprint: fingerprint}) do
    [verify_fun: {&ssl_verify_fun/3, fingerprint}]
  end

  defp ssl_verify_fun(cert, {:bad_cert, :selfsigned_peer} = reason, {hash_alg, fingerprint}) do
    der = :public_key.pkix_encode(:OTPCertificate, cert, :otp)
    hash = :crypto.hash(hash_alg, der)

    case hash do
      ^fingerprint ->
        {:valid, {hash_alg, fingerprint}}

      _ ->
        {:fail, reason}
    end
  end

  defp ssl_verify_fun(_, :valid, state), do: {:valid, state}
  defp ssl_verify_fun(_, :valid_peer, state), do: {:valid, state}
  defp ssl_verify_fun(_, {:bad_cert, _} = reason, _), do: {:fail, reason}
  defp ssl_verify_fun(_, {:extension, _}, state), do: {:unknown, state}
end

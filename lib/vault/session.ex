defmodule Vault.Session do
  use GenServer
  require Logger

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, opts)
  end

  def init(opts) do
    vault = Keyword.fetch!(opts, :vault)
    expire_margin = Keyword.get(opts, :expire_margin, 60)
    retry_interval = Keyword.get(opts, :retry_interval, 20)

    {:ok, state} = get_token_data(%{
      vault: vault,
      expire_margin: expire_margin,
      retry_interval: retry_interval,
      expires_at: nil
    })

    {:ok, state} = schedule_next(state)

    {:ok, state}
  end

  def handle_info(:renew, %{retry_interval: retry_interval} = state) do
    with {:ok, state} <- renew(state),
         {:ok, state} <- get_token_data(state),
         {:ok, state} <- schedule_next(state) do
      {:noreply, state}
    else
      {:error, err} ->
        Logger.error("Vault session error: #{inspect err}")
        Process.send_after(self(), :renew, retry_interval * 1000)
        {:noreply, state}
      {:fatal, err} ->
        Logger.error("Vault session fatal error: #{inspect err}")
        {:stop, err, state}
    end
  end

  defp renew(%{vault: vault} = state) do
    case Vault.Http.post(vault, "/auth/token/renew-self", %{}) do
      {:ok, _} ->
        Logger.info("Token renewd")
        {:ok, state}
      {_, err} -> {:error, err}
    end
  end

  defp get_token_data(%{vault: vault} = state) do
    case  Vault.Http.get(vault, "/auth/token/lookup-self") do
      {:ok, %{"data" => %{"renewable" => true, "expire_time" => expires_at_s}}} when is_bitstring(expires_at_s) ->
        {:ok, %{state|expires_at: Timex.parse!(expires_at_s, "{ISO:Extended}")}}
      {:ok, %{"data" => %{"renewable" => false}}} ->
        {:fatal, {:token_not_renewable, "Token not renewable"}}
      {:ok, _} ->
        {:fatal, {:token_not_renewable, "Token does not expire"}}
      {:not_ok, err} ->
        {:fatal, err}
      {:error, err} ->
        {:error, err}
    end
  end

  defp schedule_next(%{expires_at: expires_at, expire_margin: expire_margin} = state) do
    case Timex.diff(expires_at, Timex.now(), :seconds) do
      d when d < 0 -> {:fatal, {:token_expired, "Token has expired and cannot be renewd"}}
      expire_duration ->
        renew_wait = max(0, (expire_duration - expire_margin))
        Logger.info("Vault session renew token in #{renew_wait}s")
        Process.send_after(self(), :renew, renew_wait * 1000)
        {:ok, state}
    end
  end
end

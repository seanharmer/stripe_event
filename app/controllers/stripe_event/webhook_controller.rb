module StripeEvent
  class WebhookController < ActionController::Base
    if Rails.application.config.action_controller.default_protect_from_forgery
      skip_before_action :verify_authenticity_token
    end

    def event
      event, source = verified_event
      if source
        StripeEvent.instrument(event, source: source)
      else
        StripeEvent.instrument(event)
      end
      head :ok
    rescue Stripe::SignatureVerificationError => e
      log_error(e)
      head :bad_request
    rescue StripeEvent::ProcessError
      head :unprocessable_entity
    end

    private

    def verified_event
      payload          = request.body.read
      signature        = request.headers['Stripe-Signature']
      candidates       = secrets(payload, signature)

      candidates.each_with_index do |(source, secret), i|
        begin
          event = Stripe::Webhook.construct_event(payload, signature, secret)
          return [event, source]
        rescue Stripe::SignatureVerificationError
          raise if i == candidates.length - 1
          next
        end
      end
    end

    def secrets(payload, signature)
      candidates = StripeEvent.signing_candidates
      # Only routing configuration may restrict a mount; query and body params
      # must not select the source used to authenticate a delivery.
      if request.path_parameters.key?(:stripe_event_source)
        source = request.path_parameters[:stripe_event_source].to_s
        candidates = candidates.select { |name, _| name == source }
      end
      return candidates unless candidates.empty?
      raise Stripe::SignatureVerificationError.new(
              "Cannot verify signature without a `StripeEvent.signing_secret` or `StripeEvent.signing_sources`",
              signature, http_body: payload)
    end

    def log_error(e)
      logger.error e.message
      e.backtrace.each { |line| logger.error "  #{line}" }
    end
  end
end

# Management services

When running a fleet of systems, it is common to use a central management service. Commonly, these services provide a client to be installed on each system which connects to the central service. Often, the management service requires the client to perform a one time registration.

The following example shows how to install the client into a bootc image and run it at first boot to register the system. This example assumes the management-client handles future connections to its management server, e.g. via a cron job or a separate systemd service. This example could be modified to create a persistent systemd service if that is required. The Containerfile is not optimized in order to more clearly explain each step, e.g. it's generally better to invoke RUN a single time to avoid creating multiple layers in the image.

```Dockerfile
FROM <bootc base image>

# Bake the credentials for the management service into the image.
ARG activation_key=

# Typically when using a management service, it will determine when to upgrade the system.
# So, disable bootc-fetch-apply-updates.timer if it is included in the base image.
RUN systemctl disable bootc-fetch-apply-updates.timer

# Install the client from dnf, or some other method that applies for your client.
RUN dnf install management-client -y && dnf clean all

COPY <<"EOT" /usr/lib/systemd/system/management-client.service
[Unit]
Description=Register with management client on first boot
After=network-online.target
ConditionPathExists=/etc/management-client/.register-on-first-boot

[Service]
Type=oneshot
EnvironmentFile=/etc/management-client/.credentials
ExecStartPre=/bin/rm -f /etc/management-client/.register-on-first-boot
ExecStart=/usr/bin/management-client register --activation-key ${CLIENT_ACTIVATION_KEY}
ExecStop=/bin/rm -f /etc/management-client/.credentials

[Install]
WantedBy=multi-user.target
EOT

# Link the service to run at startup.
RUN ln -s /usr/lib/systemd/system/management-client.service /usr/lib/systemd/system/multi-user.target.wants/management-client.service

# Store the credentials in a file, so it can used by the systemd service.
RUN echo -e "CLIENT_ACTIVATION_KEY=${activation_key}" > /etc/management-client/.credentials

# This file exists as a condition flag for the management-client.service.
# It will be removed once the registration finishes.
RUN touch /etc/management-client/.register-on-first-boot
```

# Runtime-verification launcher image for Umbraco-CMS (see docs/runtime-verification-study.md).
#
# The BUILD happens here (network on) so the sealed `--network=none` runtime run needs no NuGet
# restore. We build only the runnable site (Umbraco.Web.UI) and SKIP the backoffice SPA — Argo's
# runtime probes hit the API surface, which the .NET app serves regardless. SQLite = no external DB.
#
# Build:  docker build -f Dockerfile -t argo-umbraco-rt <path-to-cloned-Umbraco-CMS>
FROM mcr.microsoft.com/dotnet/sdk:10.0
WORKDIR /src
COPY . .

# GOTCHA 1 — shallow clone. Argo clones --depth 1, but Umbraco's GitVersioning (Nerdbank +
# Umbraco.GitVersioning.Extensions) needs real history to compute the version + GitCommitIdShort.
# Unshallow before building (removing .git instead breaks GetUmbracoBuildVersion).
RUN git config --global --add safe.directory '*' && (git fetch --unshallow || git fetch --deepen=100000 || true)

RUN dotnet restore src/Umbraco.Web.UI/Umbraco.Web.UI.csproj

# GOTCHA 2 — npm. The build shells out to npm in two places and there is no Node in the SDK image:
#   - StaticAssets BuildBackoffice (the SPA)  -> skipped by -p:UmbracoBuild=true (non-empty value)
#   - Umbraco.Cms.Targets package-schema codegen -> gated by !Exists(...), so pre-create the file.
RUN echo '{}' > src/Umbraco.Cms.Targets/umbraco-package-schema.json
RUN dotnet build src/Umbraco.Web.UI/Umbraco.Web.UI.csproj -c Release --no-restore -p:UmbracoBuild=true

# Boot config baked in (read at the sealed run). Unattended SQLite install, offline (no version
# check / telemetry). NOTE: GOTCHA 3 — Microsoft.Data.Sqlite rejects the `Foreground` keyword, so
# the connection string here does NOT include it (the Umbraco default template does — strip it).
ENV ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    Umbraco__CMS__Unattended__InstallUnattended=true \
    Umbraco__CMS__Unattended__UnattendedUserName="Argo Runtime" \
    Umbraco__CMS__Unattended__UnattendedUserEmail="argo@example.com" \
    Umbraco__CMS__Unattended__UnattendedUserPassword="Sup3rSecretPass123!" \
    ConnectionStrings__umbracoDbDSN="Data Source=/src/umbraco.sqlite.db;Cache=Shared;" \
    ConnectionStrings__umbracoDbDSN_ProviderName="Microsoft.Data.Sqlite" \
    Umbraco__CMS__Global__VersionCheckPeriod=0 \
    Umbraco__CMS__Global__SanitizeTinyMce=true
# To also exercise the headless Delivery API, add:  Umbraco__CMS__DeliveryApi__Enabled=true
EXPOSE 8080

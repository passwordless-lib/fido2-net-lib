#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:6.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src
COPY ["nuget.config", "."]
COPY ["BlazorWasmDemo/Server/BlazorWasmDemo.Server.csproj", "BlazorWasmDemo/Server/"]
COPY ["Src/Fido2.AspNet/Fido2.AspNet.csproj", "Src/Fido2.AspNet/"]
COPY ["Src/Fido2/Fido2.csproj", "Src/Fido2/"]
COPY ["Src/Fido2.Models/Fido2.Models.csproj", "Src/Fido2.Models/"]
COPY ["BlazorWasmDemo/Client/BlazorWasmDemo.Client.csproj", "BlazorWasmDemo/Client/"]
COPY ["Src/Fido2.BlazorWebAssembly/Fido2.BlazorWebAssembly.csproj", "Src/Fido2.BlazorWebAssembly/"]
RUN dotnet restore "BlazorWasmDemo/Server/BlazorWasmDemo.Server.csproj"
COPY . .
WORKDIR "/src/BlazorWasmDemo/Server"
RUN dotnet build "BlazorWasmDemo.Server.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "BlazorWasmDemo.Server.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "BlazorWasmDemo.Server.dll"]
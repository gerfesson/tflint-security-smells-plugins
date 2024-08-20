# tflint-security-smells-plugins
## Configurar o plugin
Necessário rodar o comando
```go build -o tflint-ruleset-security-smell```

## Cria o arquivo .tflint.hcl
Nele define o caminho para o plugin
```
plugin "tflint-ruleset-security-smell" {
    enabled = "true"
    path = "~/.tflint.d/plugins/tflint-ruleset-security-smell"
}
```
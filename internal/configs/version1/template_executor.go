package version1

import (
	"bytes"
	"path"
	"text/template"
)

// TemplateExecutor executes Edgenexus configuration templates.
type TemplateExecutor struct {
	mainTemplate    *template.Template
	ingressTemplate *template.Template
}

// NewTemplateExecutor creates a TemplateExecutor.
func NewTemplateExecutor(mainTemplatePath string, ingressTemplatePath string) (*TemplateExecutor, error) {
	// template name must be the base name of the template file https://golang.org/pkg/text/template/#Template.ParseFiles
	edgeTemplate, err := template.New(path.Base(mainTemplatePath)).ParseFiles(mainTemplatePath)
	if err != nil {
		return nil, err
	}

	ingressTemplate, err := template.New(path.Base(ingressTemplatePath)).Funcs(helperFunctions).ParseFiles(ingressTemplatePath)
	if err != nil {
		return nil, err
	}

	return &TemplateExecutor{
		mainTemplate:    edgeTemplate,
		ingressTemplate: ingressTemplate,
	}, nil
}

// UpdateMainTemplate updates the main Edgenexus template.
func (te *TemplateExecutor) UpdateMainTemplate(templateString *string) error {
	newTemplate, err := template.New("edgeTemplate").Parse(*templateString)
	if err != nil {
		return err
	}

	te.mainTemplate = newTemplate

	return nil
}

// UpdateIngressTemplate updates the ingress template.
func (te *TemplateExecutor) UpdateIngressTemplate(templateString *string) error {
	newTemplate, err := template.New("ingressTemplate").Funcs(helperFunctions).Parse(*templateString)
	if err != nil {
		return err
	}

	te.ingressTemplate = newTemplate

	return nil
}

// ExecuteMainConfigTemplate generates the content of the main Edgenexus configuration file.
func (te *TemplateExecutor) ExecuteMainConfigTemplate(cfg *MainConfig) ([]byte, error) {
	var configBuffer bytes.Buffer
	err := te.mainTemplate.Execute(&configBuffer, cfg)

	return configBuffer.Bytes(), err
}

// ExecuteIngressConfigTemplate generates the content of a Edgenexus configuration file for an Ingress resource.
func (te *TemplateExecutor) ExecuteIngressConfigTemplate(cfg *IngressEdgeConfig) ([]byte, error) {
	var configBuffer bytes.Buffer
	err := te.ingressTemplate.Execute(&configBuffer, cfg)

	return configBuffer.Bytes(), err
}

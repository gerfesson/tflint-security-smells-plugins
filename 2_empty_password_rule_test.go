package main

import (
	"testing"

	hcl "github.com/hashicorp/hcl/v2"
	"github.com/terraform-linters/tflint-plugin-sdk/helper"
)

func Test_EmptyPass(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				resource "aws_iam_user_login_profile" "example" {
				user    = aws_iam_user.example.name
				password = ""
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewEmptyPasswordRule(),
					Message: "Resource has an empty password attribute",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 16},
						End:      hcl.Pos{Line: 4, Column: 18},
					},
				},
			},
		},
	}

	rule := NewEmptyPasswordRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}

func Test_ErrorPass(t *testing.T) {
	tests := []struct {
		Name     string
		Content  string
		Expected helper.Issues
	}{
		{
			Name: "issue found",
			Content: `
				provider "aws" {
					region = "${var.aws_region}"
				}

				resource "aws_security_group" "default" {
					count = "${var.aws_security_group.sg_count}"

					name = "terraform_security_group_${lookup(var.aws_security_group, concat("sg_", count.index, "_name"))}"
					description = "AWS security group for terraform example"

					ingress {
						from_port   = "${lookup(var.aws_security_group, concat("sg_", count.index, "_from_port"))}"
						to_port     = "${lookup(var.aws_security_group, concat("sg_", count.index, "_to_port"))}"
						protocol    = "${lookup(var.aws_security_group, concat("sg_", count.index, "_protocol"))}"
						cidr_blocks = [ "0.0.0.0/0" ]
					}

					tags {
						Name = "Terraform AWS security group"
					}
						
					resource "aws_elb" "web" {
						name = "terraform"

						listener {
							instance_port       = 80
							instance_protocol   = "http"
							lb_port             = 80
							lb_protocol         = "http"
						}

						availability_zones = [
							"${aws_instance.web.*.availability_zone}"
						]

						instances = [
							"${aws_instance.web.*.id}",
						]
					}

					resource "aws_instance" "web" {
						count = 3

						instance_type = "${var.aws_instance_type}"
						ami = "${lookup(var.aws_amis, var.aws_region)}"
						availability_zone = "${lookup(var.aws_availability_zones, count.index)}"

						key_name = "${var.aws_key_name}"
						security_groups = [ "${aws_security_group.default.*.name}" ]
						associate_public_ip_address = true

						connection {
							user = "${var.aws_instance_user}"
							key_file = "${var.aws_key_path}"
						}

						provisioner "file" {
							source = "files/"
							destination = "/tmp/"
						}

						tags {
							Name = "Terraform web ${count.index}"
						}
					}
				}`,
			Expected: helper.Issues{
				{
					Rule:    NewEmptyPasswordRule(),
					Message: "Resource has an empty password attribute",
					Range: hcl.Range{
						Filename: "resource.tf",
						Start:    hcl.Pos{Line: 4, Column: 16},
						End:      hcl.Pos{Line: 4, Column: 18},
					},
				},
			},
		},
	}

	rule := NewEmptyPasswordRule()

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			runner := helper.TestRunner(t, map[string]string{"resource.tf": test.Content})

			if err := rule.Check(runner); err != nil {
				t.Fatalf("Unexpected error occurred: %s", err)
			}

			helper.AssertIssues(t, test.Expected, runner.Issues)
		})
	}
}

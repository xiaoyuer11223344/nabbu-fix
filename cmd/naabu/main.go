package main

import (
	"context"
	"os"
	"os/signal"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

func main() {

	// 解析命令行标志并读取配置文件
	options := runner.ParseOptions()

	// 通过解析创建新的runner结构实例
	naabuRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	// 设置退出信号
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			// 结束前输出扫描结果
			naabuRunner.ShowScanResultOnExit()
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			if options.ResumeCfg.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", runner.DefaultResumeFilePath())
				err = options.ResumeCfg.SaveResumeConfig()
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			naabuRunner.Close()
			os.Exit(1)
		}
	}()

	// 运行runner
	err = naabuRunner.RunEnumeration(context.TODO())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}

	// 成功执行后，删除文件
	options.ResumeCfg.CleanupResumeConfig()
}

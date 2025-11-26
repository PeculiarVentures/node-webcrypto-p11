import { readFileSync } from "node:fs";
import typescript from "rollup-plugin-typescript2";
import dts from "rollup-plugin-dts";

const pkg = JSON.parse(readFileSync("./package.json", "utf8"));

const banner = [
  "/*!",
  " * The MIT License (MIT)",
  " *",
  " * Copyright (c) 2020 Peculiar Ventures, LLC",
  " * ",
  " * See the full version of the license https://github.com/PeculiarVentures/node-webcrypto-p11/blob/master/LICENSE",
  " */",
  "",
].join("\n");
const input = "src/index.ts";
const external = Object.keys({
  ...pkg.dependencies || {},
  crypto: 0,
});

export default [
  {
    input,
    plugins: [
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
            target: "ES2019",
            module: "ES2015",
            removeComments: true,
          }
        }
      }),
    ],
    external: [...external],
    output: [
      {
        banner,
        file: pkg.main,
        format: "cjs",
      },
      {
        banner,
        file: pkg.module,
        format: "es",
      },
    ],
  },
  {
    input,
    external: [...external],
    plugins: [
      dts()
    ],
    output: [
      {
        banner,
        file: pkg.types,
      }
    ]
  },
];
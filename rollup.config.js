import typescript from "rollup-plugin-typescript2";
import dts from "rollup-plugin-dts";
import path from "path";
import pkg from "./package.json";

const banner = [
  "/*!",
  " Copyright (c) Peculiar Ventures, LLC",
  "*/",
  "",
].join("\n");
const input = "src/index.ts";
const external = [
  ...["crypto"],
  ...Object.keys(pkg.dependencies || {}),
];

export default [
  {
    input,
    plugins: [
      typescript({
        check: true,
        clean: true,
        tsconfigOverride: {
          compilerOptions: {
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
      dts({
        tsconfig: path.resolve(__dirname, "./tsconfig.json")
      })
    ],
    output: [
      {
        banner,
        file: pkg.types,
      }
    ]
  },
];
